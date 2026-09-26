package com.github.guoyyit.securitybaselinedriftjava.service;

import com.github.guoyyit.securitybaselinedriftjava.config.ServiceProperties;
import com.github.guoyyit.securitybaselinedriftjava.engine.CheckEngine;
import com.github.guoyyit.securitybaselinedriftjava.model.Baseline;
import com.github.guoyyit.securitybaselinedriftjava.model.BaselineSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.model.CheckReport;
import com.github.guoyyit.securitybaselinedriftjava.model.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.model.Exemption;
import com.github.guoyyit.securitybaselinedriftjava.model.Finding;
import com.github.guoyyit.securitybaselinedriftjava.model.FindingStatus;
import com.github.guoyyit.securitybaselinedriftjava.model.Rule;
import com.github.guoyyit.securitybaselinedriftjava.model.RuleSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.model.SubmissionResult;
import com.github.guoyyit.securitybaselinedriftjava.store.BaselineStore;
import com.github.guoyyit.securitybaselinedriftjava.store.CheckpointStore;
import com.github.guoyyit.securitybaselinedriftjava.store.ExemptionStore;
import com.github.guoyyit.securitybaselinedriftjava.store.FindingStore;
import com.github.guoyyit.securitybaselinedriftjava.store.RuleSetStore;
import com.github.guoyyit.securitybaselinedriftjava.store.SnapshotStore;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Facade orchestrating snapshot submission, versioned rule/baseline updates,
 * incremental checking, finding lifecycle and crash recovery.
 *
 * Consistency: mutations run under the write lock, queries under the read lock.
 * A check run captures immutable version references up front, so it always
 * evaluates one complete, unmixed configuration generation, and every mutation
 * is followed by an atomic checkpoint commit.
 */
@Service
public class DriftDetectionService {

    private final SnapshotStore snapshotStore;
    private final RuleSetStore ruleSetStore;
    private final BaselineStore baselineStore;
    private final ExemptionStore exemptionStore;
    private final FindingStore findingStore;
    private final CheckEngine checkEngine;
    private final EvaluationCache cache;
    private final CheckpointStore checkpointStore;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();

    private long committedSequence;

    public DriftDetectionService(SnapshotStore snapshotStore,
                                 RuleSetStore ruleSetStore,
                                 BaselineStore baselineStore,
                                 ExemptionStore exemptionStore,
                                 FindingStore findingStore,
                                 CheckEngine checkEngine,
                                 ServiceProperties properties) {
        this.snapshotStore = snapshotStore;
        this.ruleSetStore = ruleSetStore;
        this.baselineStore = baselineStore;
        this.exemptionStore = exemptionStore;
        this.findingStore = findingStore;
        this.checkEngine = checkEngine;
        this.cache = new EvaluationCache(properties.getCacheMaxEntries());
        this.checkpointStore = new CheckpointStore(Path.of(properties.getCheckpointDir()));
        recover();
    }

    /** Crash recovery: resume from the last committed position exactly once. */
    private void recover() {
        Optional<CheckpointStore.SystemState> state = checkpointStore.loadLastCommitted();
        if (state.isEmpty()) {
            this.committedSequence = 0;
            return;
        }
        CheckpointStore.SystemState s = state.get();
        snapshotStore.restore(s.snapshots());
        s.ruleSets().forEach(ruleSetStore::restore);
        s.baselineSets().forEach(baselineStore::restore);
        if (s.exemptions() != null) {
            exemptionStore.restore(s.exemptions());
        }
        findingStore.restore(s.findings().stream().map(CheckpointStore.FindingData::toFinding).toList());
        this.committedSequence = s.sequence();
    }

    public SubmissionResult submitSnapshot(ConfigSnapshot snapshot) {
        lock.writeLock().lock();
        try {
            SubmissionResult result = snapshotStore.submit(snapshot);
            if (result.accepted()) {
                // Only a newer snapshot can change the compliance outcome.
                evaluateAndApply(snapshot);
                commit();
            }
            return result;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public long publishRules(List<Rule> rules) {
        lock.writeLock().lock();
        try {
            long version = ruleSetStore.publish(rules);
            recheckAllSources();
            commit();
            return version;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public long publishBaselines(List<Baseline> baselines) {
        lock.writeLock().lock();
        try {
            long version = baselineStore.publish(baselines);
            recheckAllSources();
            commit();
            return version;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public long replaceExemptions(List<Exemption> exemptions) {
        lock.writeLock().lock();
        try {
            long version = exemptionStore.replaceAll(exemptions);
            recheckAllSources();
            commit();
            return version;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public CheckReport checkSource(String sourceId) {
        lock.writeLock().lock();
        try {
            Optional<ConfigSnapshot> snapshot = snapshotStore.latest(sourceId);
            if (snapshot.isEmpty()) {
                return null;
            }
            CheckReport report = evaluateAndApply(snapshot.get());
            commit();
            return report;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public List<CheckReport> checkAll() {
        lock.writeLock().lock();
        try {
            List<CheckReport> reports = new ArrayList<>();
            for (ConfigSnapshot snapshot : snapshotStore.allLatest()) {
                reports.add(evaluateAndApply(snapshot));
            }
            commit();
            return reports;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public List<Finding> findings(Optional<FindingStatus> status) {
        lock.readLock().lock();
        try {
            return status.map(findingStore::byStatus).orElseGet(findingStore::all);
        } finally {
            lock.readLock().unlock();
        }
    }

    public Optional<Finding> acknowledge(String fingerprint) {
        lock.writeLock().lock();
        try {
            Optional<Finding> f = findingStore.acknowledge(fingerprint);
            f.ifPresent(x -> commit());
            return f;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public long committedSequence() {
        lock.readLock().lock();
        try {
            return committedSequence;
        } finally {
            lock.readLock().unlock();
        }
    }

    // ---- internals (write lock held by callers) ----

    private void recheckAllSources() {
        for (ConfigSnapshot snapshot : snapshotStore.allLatest()) {
            evaluateAndApply(snapshot);
        }
    }

    /**
     * Incremental evaluation: unchanged snapshot + unchanged rule/baseline/exemption
     * versions hit the bounded cache; anything changed misses and is re-evaluated.
     */
    private CheckReport evaluateAndApply(ConfigSnapshot snapshot) {
        RuleSetVersion rules = ruleSetStore.current();
        BaselineSetVersion baselines = baselineStore.current();
        ExemptionStore.ExemptionSet exemptions = exemptionStore.current();
        String key = EvaluationCache.key(snapshot, rules.version(), baselines.version(), exemptions.version());
        CheckReport report = cache.get(key)
                // Cache hit: violations are content-identical, but volatile metadata
                // (snapshot version, versions, fromCache) must reflect THIS run.
                .map(hit -> new CheckReport(snapshot.sourceId(), snapshot.version(),
                        rules.version(), baselines.version(), exemptions.version(),
                        hit.violations(), hit.explanations(), true))
                .orElseGet(() -> {
                    CheckReport fresh = checkEngine.evaluate(snapshot, rules, baselines, exemptions);
                    cache.put(key, fresh);
                    return fresh;
                });
        findingStore.applyReport(report);
        return report;
    }

    /** Atomic checkpoint commit; advances the committed position. */
    private void commit() {
        List<RuleSetVersion> ruleVersions = ruleSetStore.versions().stream()
                .map(v -> ruleSetStore.version(v).orElseThrow())
                .toList();
        List<BaselineSetVersion> baselineVersions = baselineStore.versions().stream()
                .map(v -> baselineStore.version(v).orElseThrow())
                .toList();
        CheckpointStore.SystemState state = new CheckpointStore.SystemState(
                committedSequence + 1,
                List.copyOf(snapshotStore.allLatest()),
                ruleVersions,
                baselineVersions,
                exemptionStore.current(),
                findingStore.all().stream().map(CheckpointStore.FindingData::from).toList());
        committedSequence = checkpointStore.commit(state);
    }
}
