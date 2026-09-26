package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.config.ServiceProperties;
import com.github.guoyyit.securitybaselinedriftjava.engine.CheckEngine;
import com.github.guoyyit.securitybaselinedriftjava.engine.ScopeResolver;
import com.github.guoyyit.securitybaselinedriftjava.model.Baseline;
import com.github.guoyyit.securitybaselinedriftjava.model.CheckReport;
import com.github.guoyyit.securitybaselinedriftjava.model.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.model.Finding;
import com.github.guoyyit.securitybaselinedriftjava.model.Operator;
import com.github.guoyyit.securitybaselinedriftjava.model.Rule;
import com.github.guoyyit.securitybaselinedriftjava.model.Scope;
import com.github.guoyyit.securitybaselinedriftjava.model.Severity;
import com.github.guoyyit.securitybaselinedriftjava.service.DriftDetectionService;
import com.github.guoyyit.securitybaselinedriftjava.store.BaselineStore;
import com.github.guoyyit.securitybaselinedriftjava.store.ExemptionStore;
import com.github.guoyyit.securitybaselinedriftjava.store.FindingStore;
import com.github.guoyyit.securitybaselinedriftjava.store.RuleSetStore;
import com.github.guoyyit.securitybaselinedriftjava.store.SnapshotStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Snapshot submission, rule/baseline updates and queries run concurrently;
 * every query must observe a consistent state and the final state must reflect
 * the newest snapshots and the last published configuration generation.
 */
class ConcurrencyConsistencyTest {

    @TempDir
    Path checkpointDir;

    @Test
    void concurrentWritesAndQueriesStayConsistent() throws Exception {
        ServiceProperties props = new ServiceProperties();
        props.setCheckpointDir(checkpointDir.toString());
        props.setCacheMaxEntries(256);
        DriftDetectionService svc = new DriftDetectionService(
                new SnapshotStore(), new RuleSetStore(), new BaselineStore(),
                new ExemptionStore(), new FindingStore(),
                new CheckEngine(new ScopeResolver()), props);

        int sources = 8;
        int snapshotsPerSource = 25;
        int rulePublishes = 10;
        ExecutorService pool = Executors.newFixedThreadPool(12);
        CountDownLatch start = new CountDownLatch(1);
        List<Throwable> errors = new CopyOnWriteArrayList<>();

        // Snapshot submitters (including out-of-order duplicates).
        for (int s = 0; s < sources; s++) {
            final String sourceId = "host-" + s;
            pool.submit(() -> {
                try {
                    start.await();
                    for (int v = 1; v <= snapshotsPerSource; v++) {
                        svc.submitSnapshot(new ConfigSnapshot(sourceId, v, Instant.now(),
                                Map.of("password.min.length", v % 2 == 0 ? "12" : "8")));
                        if (v > 1) {
                            // late duplicate of an older version: must be ignored safely
                            svc.submitSnapshot(new ConfigSnapshot(sourceId, v - 1, Instant.now(),
                                    Map.of("password.min.length", "8")));
                        }
                    }
                } catch (Throwable t) {
                    errors.add(t);
                }
            });
        }
        // Rule publisher.
        pool.submit(() -> {
            try {
                start.await();
                for (int i = 0; i < rulePublishes; i++) {
                    svc.publishRules(List.of(new Rule("pwd-policy", Scope.global(),
                            "password.min.length", Operator.EQUALS, "12",
                            Severity.HIGH, "password policy mismatch")));
                }
            } catch (Throwable t) {
                errors.add(t);
            }
        });
        // Baseline publisher.
        pool.submit(() -> {
            try {
                start.await();
                for (int i = 0; i < rulePublishes; i++) {
                    svc.publishBaselines(List.of(new Baseline("base", Scope.global(),
                            Map.of("tls.version", "1.3"))));
                }
            } catch (Throwable t) {
                errors.add(t);
            }
        });
        // Concurrent readers: every observation must be internally consistent.
        for (int r = 0; r < 2; r++) {
            pool.submit(() -> {
                try {
                    start.await();
                    for (int i = 0; i < 200; i++) {
                        List<Finding> findings = svc.findings(Optional.empty());
                        for (Finding f : findings) {
                            assertNotNull(f.getFingerprint());
                            assertNotNull(f.getStatus());
                        }
                        long seq = svc.committedSequence();
                        assertTrue(seq >= 0);
                    }
                } catch (Throwable t) {
                    errors.add(t);
                }
            });
        }

        start.countDown();
        pool.shutdown();
        assertTrue(pool.awaitTermination(60, TimeUnit.SECONDS));
        assertEquals(List.of(), errors.stream().map(Throwable::toString).toList());

        // Final state: latest snapshot version per source, final rule generation.
        List<CheckReport> reports = svc.checkAll();
        assertEquals(sources, reports.size());
        long finalRuleVersion = reports.get(0).ruleSetVersion();
        assertEquals(rulePublishes, finalRuleVersion);
        for (CheckReport r : reports) {
            assertEquals(snapshotsPerSource, r.snapshotVersion());
            assertEquals(finalRuleVersion, r.ruleSetVersion());
        }
        // No duplicate findings by fingerprint.
        List<String> fps = svc.findings(Optional.empty()).stream().map(Finding::getFingerprint).toList();
        assertEquals(fps.size(), fps.stream().distinct().count());
    }
}
