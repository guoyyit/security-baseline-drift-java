package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.config.DriftProperties;
import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.Rule;
import com.github.guoyyit.securitybaselinedriftjava.domain.RuleSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.Scope;
import com.github.guoyyit.securitybaselinedriftjava.domain.Severity;
import com.github.guoyyit.securitybaselinedriftjava.engine.EvaluationEngine;
import com.github.guoyyit.securitybaselinedriftjava.service.DriftService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Incremental evaluation: unchanged inputs hit the cache; version bumps invalidate it. */
class IncrementalEvaluationTest {

    @TempDir
    Path tempDir;

    private DriftService newService(DriftProperties props) {
        props.setJournalDir(tempDir.toString());
        return new DriftService(props, tempDir.resolve("journal.log"));
    }

    private static RuleSetVersion rule(long version, String expected) {
        return new RuleSetVersion(version, List.of(new Rule(
                "r-mode", "mode check", Scope.global(),
                "app.mode", Rule.Operator.EQUALS, expected, Severity.LOW)),
                Instant.now());
    }

    @Test
    void unchangedSnapshotAndRulesAreServedFromCache() {
        try (DriftService service = newService(new DriftProperties())) {
            service.publishRuleSet(rule(1, "strict"));
            service.submitSnapshot(new ConfigSnapshot("s1", Set.of(), 1, Instant.now(),
                    Map.of("app.mode", "strict")));

            var first = service.evaluateNow("s1");
            // second evaluateNow with identical inputs must hit the incremental cache
            var second = service.evaluateNow("s1");
            assertTrue(second.fromCache(), "unchanged snapshot + rules must be served from cache");
            assertEquals(first.violations(), second.violations());
        }
    }

    @Test
    void ruleUpdateInvalidatesCache() {
        DriftProperties props = new DriftProperties();
        props.setEvaluateOnRuleUpdate(false); // defer re-evaluation to observe the cache directly
        try (DriftService service = newService(props)) {
            service.publishRuleSet(rule(1, "strict"));
            service.submitSnapshot(new ConfigSnapshot("s1", Set.of(), 1, Instant.now(),
                    Map.of("app.mode", "strict")));
            assertTrue(service.evaluateNow("s1").fromCache(), "warm cache before the update");

            service.publishRuleSet(rule(2, "relaxed"));
            var afterUpdate = service.evaluateNow("s1");
            assertFalse(afterUpdate.fromCache(), "rule version bump must invalidate the cache");
            assertEquals(2, afterUpdate.ruleSetVersion());
        }
    }

    @Test
    void newSnapshotVersionInvalidatesCache() {
        try (DriftService service = newService(new DriftProperties())) {
            service.publishRuleSet(rule(1, "strict"));
            service.submitSnapshot(new ConfigSnapshot("s1", Set.of(), 1, Instant.now(),
                    Map.of("app.mode", "strict")));
            var resubmitted = service.submitSnapshot(new ConfigSnapshot("s1", Set.of(), 2,
                    Instant.now(), Map.of("app.mode", "strict")));
            assertFalse(resubmitted.evaluation().fromCache(),
                    "a new snapshot version must be re-evaluated, not served from cache");
        }
    }

    @Test
    void cacheMemoryIsBounded() {
        DriftProperties props = new DriftProperties();
        props.setEvalCacheMaxSize(8);
        try (DriftService service = newService(props)) {
            service.publishRuleSet(rule(1, "strict"));
            // submit many distinct sources with large snapshots
            for (int i = 0; i < 100; i++) {
                Map<String, String> configs = new HashMap<>();
                for (int k = 0; k < 500; k++) {
                    configs.put("key." + k, "value-" + k);
                }
                configs.put("app.mode", "strict");
                service.submitSnapshot(new ConfigSnapshot("src-" + i, Set.of(), 1,
                        Instant.now(), configs));
            }
            EvaluationEngine engineProbe = new EvaluationEngine(8);
            for (int i = 0; i < 100; i++) {
                engineProbe.evaluateCached(
                        new ConfigSnapshot("probe-" + i, Set.of(), 1, Instant.now(),
                                Map.of("app.mode", "strict")),
                        rule(1, "strict"),
                        new com.github.guoyyit.securitybaselinedriftjava.domain.BaselineSetVersion(
                                0, List.of(), Instant.EPOCH),
                        List.of(), 0, Instant.now());
            }
            assertTrue(engineProbe.cacheSize() <= 8,
                    "LRU cache must stay bounded, got " + engineProbe.cacheSize());
        }
    }
}
