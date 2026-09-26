package com.github.guoyyit.securitybaselinedriftjava.service;

import com.github.guoyyit.securitybaselinedriftjava.config.DriftProperties;
import com.github.guoyyit.securitybaselinedriftjava.domain.BaselineSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.Exemption;
import com.github.guoyyit.securitybaselinedriftjava.domain.Finding;
import com.github.guoyyit.securitybaselinedriftjava.domain.FindingStatus;
import com.github.guoyyit.securitybaselinedriftjava.domain.RuleSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.Violation;
import com.github.guoyyit.securitybaselinedriftjava.engine.EvaluatedViolation;
import com.github.guoyyit.securitybaselinedriftjava.engine.EvaluationEngine;
import com.github.guoyyit.securitybaselinedriftjava.engine.EvaluationResult;
import com.github.guoyyit.securitybaselinedriftjava.store.BaselineSetStore;
import com.github.guoyyit.securitybaselinedriftjava.store.ExemptionStore;
import com.github.guoyyit.securitybaselinedriftjava.store.FindingStore;
import com.github.guoyyit.securitybaselinedriftjava.store.RuleSetStore;
import com.github.guoyyit.securitybaselinedriftjava.store.SnapshotStore;
import com.github.guoyyit.securitybaselinedriftjava.store.journal.Journal;
import com.github.guoyyit.securitybaselinedriftjava.store.journal.JournalRecord;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Facade coordinating stores, engine and journal.
 *
 * <p>Consistency model: every mutation takes the write lock, appends to the
 * journal (fsync) and only then applies to in-memory stores; each evaluation
 * captures immutable version references once, so it always sees one complete
 * rule/baseline version. Queries take the read lock and therefore observe the
 * state either fully before or fully after a committed mutation — never a mix.
 *
 * <p>Recovery: replaying the journal rebuilds the exact committed state; a
 * reconcile pass then re-evaluates the latest snapshots idempotently, so a
 * crash between "snapshot committed" and "evaluation committed" neither loses
 * nor duplicates findings, and a torn journal tail is discarded on open.
 */
public class DriftService implements AutoCloseable {

    /** Result of a snapshot submission. */
    public record SubmissionResult(SnapshotStore.AcceptResult acceptResult, EvaluationResult evaluation) {
    }

    private static final RuleSetVersion EMPTY_RULES = new RuleSetVersion(0, List.of(), Instant.EPOCH);
    private static final BaselineSetVersion EMPTY_BASELINE = new BaselineSetVersion(0, List.of(), Instant.EPOCH);

    private final SnapshotStore snapshotStore = new SnapshotStore();
    private final RuleSetStore ruleSetStore = new RuleSetStore();
    private final BaselineSetStore baselineSetStore = new BaselineSetStore();
    private final ExemptionStore exemptionStore = new ExemptionStore();
    private final FindingStore findingStore = new FindingStore();
    private final EvaluationEngine engine;
    private final Journal journal;
    private final DriftProperties properties;
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final AtomicLong evalSeq = new AtomicLong(0);

    public DriftService(DriftProperties properties) {
        this.properties = properties;
        this.engine = new EvaluationEngine(properties.getEvalCacheMaxSize());
        this.journal = new Journal(Path.of(properties.getJournalDir(), "drift-journal.log"));
    }

    /** Test constructor allowing a custom journal path. */
    public DriftService(DriftProperties properties, Path journalFile) {
        this.properties = properties;
        this.engine = new EvaluationEngine(properties.getEvalCacheMaxSize());
        this.journal = new Journal(journalFile);
    }

    // ---- mutations (write lock, journaled before applied) ----

    /** Submit a snapshot; accepted snapshots are journaled then evaluated. */
    public SubmissionResult submitSnapshot(ConfigSnapshot snapshot) {
        lock.writeLock().lock();
        try {
            if (snapshotStore.isStale(snapshot)) {
                // idempotent: duplicate / out-of-order / late snapshots change nothing
                return new SubmissionResult(SnapshotStore.AcceptResult.DUPLICATE_OR_STALE, null);
            }
            // WAL: journal first, then apply (write lock serializes check-and-set)
            journal.append(new JournalRecord.SnapshotAccepted(snapshot));
            snapshotStore.accept(snapshot);
            EvaluationResult result = evaluateLocked(snapshot.sourceId());
            return new SubmissionResult(SnapshotStore.AcceptResult.ACCEPTED, result);
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** Publish a new rule set version and re-evaluate all sources. */
    public void publishRuleSet(RuleSetVersion ruleSet) {
        lock.writeLock().lock();
        try {
            journal.append(new JournalRecord.RuleSetCommitted(ruleSet));
            ruleSetStore.publish(ruleSet);
            engine.invalidateAll();
            if (properties.isEvaluateOnRuleUpdate()) {
                reevaluateAllLocked();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    /** Publish a new baseline set version and re-evaluate all sources. */
    public void publishBaselineSet(BaselineSetVersion baselineSet) {
        lock.writeLock().lock();
        try {
            journal.append(new JournalRecord.BaselineSetCommitted(baselineSet));
            baselineSetStore.publish(baselineSet);
            engine.invalidateAll();
            if (properties.isEvaluateOnRuleUpdate()) {
                reevaluateAllLocked();
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    public void addExemption(Exemption exemption) {
        lock.writeLock().lock();
        try {
            journal.append(new JournalRecord.ExemptionAdded(exemption));
            exemptionStore.add(exemption);
            engine.invalidateAll();
            reevaluateAllLocked();
        } finally {
            lock.writeLock().unlock();
        }
    }

    public boolean removeExemption(String exemptionId) {
        lock.writeLock().lock();
        try {
            journal.append(new JournalRecord.ExemptionRemoved(exemptionId));
            boolean removed = exemptionStore.remove(exemptionId);
            engine.invalidateAll();
            reevaluateAllLocked();
            return removed;
        } finally {
            lock.writeLock().unlock();
        }
    }

    public Optional<Finding> acknowledge(String fingerprint, String operator) {
        lock.writeLock().lock();
        try {
            if (findingStore.byFingerprint(fingerprint).isEmpty()) {
                return Optional.empty();
            }
            // WAL: journal first, then apply
            journal.append(new JournalRecord.FindingAcknowledged(fingerprint, operator));
            return findingStore.acknowledge(fingerprint, operator);
        } finally {
            lock.writeLock().unlock();
        }
    }

    // ---- queries (read lock: see a consistent committed state) ----

    public List<Finding> findings(String sourceId) {
        lock.readLock().lock();
        try {
            return findingStore.bySource(sourceId);
        } finally {
            lock.readLock().unlock();
        }
    }

    public List<Finding> allFindings() {
        lock.readLock().lock();
        try {
            return List.copyOf(findingStore.all());
        } finally {
            lock.readLock().unlock();
        }
    }

    public Optional<Finding> finding(String fingerprint) {
        lock.readLock().lock();
        try {
            return findingStore.byFingerprint(fingerprint);
        } finally {
            lock.readLock().unlock();
        }
    }

    public Optional<ConfigSnapshot> latestSnapshot(String sourceId) {
        lock.readLock().lock();
        try {
            return snapshotStore.latest(sourceId);
        } finally {
            lock.readLock().unlock();
        }
    }

    public Optional<RuleSetVersion> currentRuleSet() {
        lock.readLock().lock();
        try {
            return ruleSetStore.current();
        } finally {
            lock.readLock().unlock();
        }
    }

    public Optional<BaselineSetVersion> currentBaselineSet() {
        lock.readLock().lock();
        try {
            return baselineSetStore.current();
        } finally {
            lock.readLock().unlock();
        }
    }

    /** Re-evaluate one source against current versions (used after recovery). */
    public EvaluationResult evaluateNow(String sourceId) {
        lock.writeLock().lock();
        try {
            return evaluateLocked(sourceId);
        } finally {
            lock.writeLock().unlock();
        }
    }

    // ---- recovery ----

    /** Recover state from the journal; must be called before serving traffic. */
    public void recover() {
        lock.writeLock().lock();
        try {
            // per-source position of the last committed evaluation
            Map<String, long[]> committedEval = new HashMap<>();
            journal.replay(record -> {
                apply(record);
                if (record instanceof JournalRecord.EvaluationCommitted r) {
                    committedEval.put(r.sourceId(), new long[]{
                            r.snapshotVersion(), r.ruleSetVersion(),
                            r.baselineVersion(), r.exemptionVersion()});
                }
            });
            engine.invalidateAll();
            // reconcile from the last committed position: only re-evaluate sources
            // whose latest state was never committed by a completed evaluation.
            long ruleVersion = ruleSetStore.current().map(RuleSetVersion::version).orElse(0L);
            long baselineVersion = baselineSetStore.current().map(BaselineSetVersion::version).orElse(0L);
            long exemptionVersion = exemptionStore.version();
            for (ConfigSnapshot snapshot : snapshotStore.allLatest()) {
                long[] committed = committedEval.get(snapshot.sourceId());
                boolean upToDate = committed != null
                        && committed[0] == snapshot.version()
                        && committed[1] == ruleVersion
                        && committed[2] == baselineVersion
                        && committed[3] == exemptionVersion;
                if (!upToDate) {
                    evaluateLocked(snapshot.sourceId());
                }
            }
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void apply(JournalRecord record) {
        if (record instanceof JournalRecord.SnapshotAccepted r) {
            snapshotStore.restore(r.snapshot());
        } else if (record instanceof JournalRecord.RuleSetCommitted r) {
            ruleSetStore.restore(r.ruleSet());
        } else if (record instanceof JournalRecord.BaselineSetCommitted r) {
            baselineSetStore.restore(r.baselineSet());
        } else if (record instanceof JournalRecord.ExemptionAdded r) {
            exemptionStore.restoreAdd(r.exemption());
        } else if (record instanceof JournalRecord.ExemptionRemoved r) {
            exemptionStore.restoreRemove(r.exemptionId());
        } else if (record instanceof JournalRecord.FindingAcknowledged r) {
            findingStore.acknowledge(r.fingerprint(), r.operator());
        } else if (record instanceof JournalRecord.EvaluationCommitted r) {
            r.upserted().forEach(findingStore::upsert);
            evalSeq.accumulateAndGet(r.evalId(), Math::max);
        } else {
            throw new IllegalStateException("unknown journal record: " + record);
        }
    }

    // ---- evaluation internals (write lock must be held) ----

    private void reevaluateAllLocked() {
        for (ConfigSnapshot snapshot : snapshotStore.allLatest()) {
            evaluateLocked(snapshot.sourceId());
        }
    }

    private EvaluationResult evaluateLocked(String sourceId) {
        ConfigSnapshot snapshot = snapshotStore.latest(sourceId)
                .orElseThrow(() -> new IllegalStateException("no snapshot for source " + sourceId));
        // capture immutable version references once: one complete version view
        RuleSetVersion ruleSet = ruleSetStore.current().orElse(EMPTY_RULES);
        BaselineSetVersion baselineSet = baselineSetStore.current().orElse(EMPTY_BASELINE);
        List<Exemption> exemptions = exemptionStore.snapshot();
        long exemptionVersion = exemptionStore.version();

        Instant now = Instant.now();
        EvaluationEngine.Evaluation evaluation = engine.evaluateCached(
                snapshot, ruleSet, baselineSet, exemptions, exemptionVersion, now);
        List<EvaluatedViolation> evaluated = evaluation.violations();

        long evalId = evalSeq.incrementAndGet();
        List<Finding> upserted = computeTransitions(sourceId, evaluated, evalId,
                ruleSet.version(), baselineSet.version(), now);

        // atomic commit: one journal record carries all transitions of this eval
        journal.append(new JournalRecord.EvaluationCommitted(evalId, sourceId,
                snapshot.version(), ruleSet.version(), baselineSet.version(),
                exemptionVersion, upserted));
        upserted.forEach(findingStore::upsert);

        List<Violation> violations = evaluated.stream().map(EvaluatedViolation::violation).toList();
        return new EvaluationResult(evalId, sourceId, snapshot.version(),
                ruleSet.version(), baselineSet.version(), violations, upserted, evaluation.fromCache());
    }

    /**
     * Compute finding lifecycle transitions for one evaluation. Idempotent:
     * re-running the same evaluation over the same finding state yields no
     * transitions, which is what makes crash-recovery reconcile safe.
     */
    private List<Finding> computeTransitions(String sourceId, List<EvaluatedViolation> violations,
                                             long evalId, long ruleSetVersion, long baselineVersion,
                                             Instant now) {
        List<Finding> upserts = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (EvaluatedViolation ev : violations) {
            Violation v = ev.violation();
            String fingerprint = v.fingerprint();
            seen.add(fingerprint);
            boolean suppressed = ev.suppressedByExemptionId() != null;
            Optional<Finding> existing = findingStore.byFingerprint(fingerprint);
            if (existing.isEmpty()) {
                upserts.add(new Finding(fingerprint, v.sourceId(), v.ruleId(), v.configKey(),
                        v.scope(), v.severity(), v.expectedValue(), v.actualValue(),
                        suppressed ? FindingStatus.SUPPRESSED : FindingStatus.NEW,
                        evalId, evalId, now, now, null, null,
                        ev.suppressedByExemptionId(), ruleSetVersion, baselineVersion));
                continue;
            }
            Finding current = existing.get();
            FindingStatus next;
            if (suppressed) {
                next = FindingStatus.SUPPRESSED;
            } else {
                next = switch (current.status()) {
                    case NEW -> FindingStatus.OPEN;            // still present: 持续
                    case OPEN, ACKNOWLEDGED -> current.status();
                    case SUPPRESSED -> FindingStatus.OPEN;     // exemption gone, still violated
                    case RESOLVED -> FindingStatus.OPEN;       // reopened after 解除
                };
            }
            boolean changed = next != current.status()
                    || !Objects.equals(current.actualValue(), v.actualValue())
                    || !Objects.equals(current.expectedValue(), v.expectedValue())
                    || !Objects.equals(current.suppressedByExemptionId(), ev.suppressedByExemptionId())
                    || current.ruleSetVersion() != ruleSetVersion
                    || current.baselineVersion() != baselineVersion;
            if (changed) {
                upserts.add(new Finding(fingerprint, current.sourceId(), current.ruleId(),
                        current.configKey(), v.scope(), v.severity(), v.expectedValue(), v.actualValue(),
                        next, current.firstSeenEvalId(), evalId, current.firstSeenAt(), now,
                        next == FindingStatus.RESOLVED ? now : null,
                        current.acknowledgedBy(), ev.suppressedByExemptionId(),
                        ruleSetVersion, baselineVersion));
            }
        }
        // findings of this source no longer violated -> RESOLVED (解除)
        for (Finding f : findingStore.bySource(sourceId)) {
            if (f.isActive() && !seen.contains(f.fingerprint())) {
                upserts.add(new Finding(f.fingerprint(), f.sourceId(), f.ruleId(), f.configKey(),
                        f.scope(), f.severity(), f.expectedValue(), f.actualValue(),
                        FindingStatus.RESOLVED, f.firstSeenEvalId(), evalId, f.firstSeenAt(), now,
                        now, f.acknowledgedBy(), null, ruleSetVersion, baselineVersion));
            }
        }
        return upserts;
    }

    @Override
    public void close() {
        lock.writeLock().lock();
        try {
            journal.close();
        } finally {
            lock.writeLock().unlock();
        }
    }
}
