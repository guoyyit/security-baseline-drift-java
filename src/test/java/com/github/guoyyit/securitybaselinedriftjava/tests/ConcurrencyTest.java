package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.config.DriftProperties;
import com.github.guoyyit.securitybaselinedriftjava.domain.BaselineEntry;
import com.github.guoyyit.securitybaselinedriftjava.domain.BaselineSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.Finding;
import com.github.guoyyit.securitybaselinedriftjava.domain.Rule;
import com.github.guoyyit.securitybaselinedriftjava.domain.RuleSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.Scope;
import com.github.guoyyit.securitybaselinedriftjava.domain.Severity;
import com.github.guoyyit.securitybaselinedriftjava.service.DriftService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Snapshot submission, rule/baseline updates and queries running concurrently. */
class ConcurrencyTest {

    @TempDir
    Path tempDir;

    @Test
    void concurrentWritersAndReadersSeeConsistentStates() throws Exception {
        DriftProperties props = new DriftProperties();
        props.setJournalDir(tempDir.toString());
        try (DriftService service = new DriftService(props, tempDir.resolve("journal.log"))) {
            int sources = 8;
            int snapshotsPerSource = 20;
            int ruleVersions = 5;
            ExecutorService pool = Executors.newFixedThreadPool(12);
            CountDownLatch start = new CountDownLatch(1);
            List<Future<?>> futures = new ArrayList<>();
            AtomicInteger queryCount = new AtomicInteger();

            // snapshot submitters (one thread per source keeps per-source order)
            for (int s = 0; s < sources; s++) {
                final String sourceId = "src-" + s;
                futures.add(pool.submit(() -> {
                    await(start);
                    for (int v = 1; v <= snapshotsPerSource; v++) {
                        service.submitSnapshot(new ConfigSnapshot(sourceId, Set.of(), v,
                                Instant.now(), Map.of("app.mode", v % 2 == 0 ? "strict" : "loose")));
                    }
                }));
            }
            // rule set publisher
            futures.add(pool.submit(() -> {
                await(start);
                for (int v = 1; v <= ruleVersions; v++) {
                    service.publishRuleSet(new RuleSetVersion(v, List.of(new Rule(
                            "r-mode", "mode", Scope.global(), "app.mode",
                            Rule.Operator.EQUALS, "strict", Severity.LOW)), Instant.now()));
                }
            }));
            // baseline publisher
            futures.add(pool.submit(() -> {
                await(start);
                for (int v = 1; v <= ruleVersions; v++) {
                    service.publishBaselineSet(new BaselineSetVersion(v, List.of(
                            new BaselineEntry(Scope.global(), "app.region", "cn",
                                    Severity.LOW, v, 0)), Instant.now()));
                }
            }));
            // concurrent readers: every observed finding must reference a complete,
            // actually published rule set version (never a field-level mix)
            for (int r = 0; r < 3; r++) {
                futures.add(pool.submit(() -> {
                    await(start);
                    for (int i = 0; i < 200; i++) {
                        for (Finding f : service.allFindings()) {
                            assertTrue(f.ruleSetVersion() >= 1 && f.ruleSetVersion() <= ruleVersions,
                                    "finding references a complete published version: " + f);
                            assertTrue(f.baselineVersion() >= 0 && f.baselineVersion() <= ruleVersions,
                                    "finding references a complete baseline version: " + f);
                        }
                        queryCount.incrementAndGet();
                    }
                }));
            }

            start.countDown();
            for (Future<?> future : futures) {
                future.get(60, TimeUnit.SECONDS);
            }
            pool.shutdown();
            assertTrue(queryCount.get() > 0);

            // after all writers finish, the final state is deterministic:
            // every source is at its latest snapshot and latest rule/baseline versions
            for (int s = 0; s < sources; s++) {
                assertEquals(snapshotsPerSource,
                        service.latestSnapshot("src-" + s).orElseThrow().version());
            }
            assertEquals(ruleVersions, service.currentRuleSet().orElseThrow().version());
            assertEquals(ruleVersions, service.currentBaselineSet().orElseThrow().version());
        }
    }

    private static void await(CountDownLatch latch) {
        try {
            latch.await();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new RuntimeException(e);
        }
    }
}
