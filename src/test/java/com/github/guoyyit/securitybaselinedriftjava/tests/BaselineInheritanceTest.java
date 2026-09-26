package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.config.DriftProperties;
import com.github.guoyyit.securitybaselinedriftjava.domain.BaselineEntry;
import com.github.guoyyit.securitybaselinedriftjava.domain.BaselineSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.FindingStatus;
import com.github.guoyyit.securitybaselinedriftjava.domain.Scope;
import com.github.guoyyit.securitybaselinedriftjava.domain.Severity;
import com.github.guoyyit.securitybaselinedriftjava.service.DriftService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Baseline inheritance: SOURCE overrides GROUP overrides GLOBAL; conflicts are explainable. */
class BaselineInheritanceTest {

    @TempDir
    Path tempDir;

    private DriftService newService() {
        DriftProperties props = new DriftProperties();
        props.setJournalDir(tempDir.toString());
        return new DriftService(props, tempDir.resolve("journal.log"));
    }

    private static BaselineSetVersion baseline(long version, long t) {
        return new BaselineSetVersion(version, List.of(
                new BaselineEntry(Scope.global(), "cache.max_memory", "512m", Severity.MEDIUM, t, 0),
                new BaselineEntry(Scope.group("bigdata"), "cache.max_memory", "4g", Severity.MEDIUM, t, 0),
                new BaselineEntry(Scope.source("node-special"), "cache.max_memory", "16g",
                        Severity.MEDIUM, t, 0)),
                Instant.now());
    }

    @Test
    void sourceOverridesGroupOverridesGlobal() {
        try (DriftService service = newService()) {
            service.publishBaselineSet(baseline(1, 1000));

            // global-only source: 512m expected
            service.submitSnapshot(new ConfigSnapshot("plain-1", Set.of(), 1, Instant.now(),
                    Map.of("cache.max_memory", "512m")));
            assertTrue(service.findings("plain-1").isEmpty(), "global baseline satisfied");

            // group member: 4g expected, 512m is drift for this source
            service.submitSnapshot(new ConfigSnapshot("bd-1", Set.of("bigdata"), 1, Instant.now(),
                    Map.of("cache.max_memory", "512m")));
            assertEquals(1, service.findings("bd-1").size(), "group baseline overrides global");
            assertEquals("4g", service.findings("bd-1").get(0).expectedValue());

            // special source: 16g expected
            service.submitSnapshot(new ConfigSnapshot("node-special", Set.of("bigdata"), 1,
                    Instant.now(), Map.of("cache.max_memory", "16g")));
            assertTrue(service.findings("node-special").isEmpty(),
                    "source-scoped baseline wins over group and global");
        }
    }

    @Test
    void sameSpecificityConflictResolvedByPriorityThenUpdateTime() {
        try (DriftService service = newService()) {
            // two GLOBAL entries for the same key: higher priority wins
            service.publishBaselineSet(new BaselineSetVersion(1, List.of(
                    new BaselineEntry(Scope.global(), "log.level", "INFO", Severity.LOW, 1000, 1),
                    new BaselineEntry(Scope.global(), "log.level", "WARN", Severity.LOW, 500, 5)),
                    Instant.now()));
            service.submitSnapshot(new ConfigSnapshot("s1", Set.of(), 1, Instant.now(),
                    Map.of("log.level", "WARN")));
            assertTrue(service.findings("s1").isEmpty(), "higher priority entry wins");

            // equal priority: later update wins
            service.publishBaselineSet(new BaselineSetVersion(2, List.of(
                    new BaselineEntry(Scope.global(), "log.level", "INFO", Severity.LOW, 1000, 0),
                    new BaselineEntry(Scope.global(), "log.level", "WARN", Severity.LOW, 2000, 0)),
                    Instant.now()));
            assertTrue(service.findings("s1").isEmpty(), "later update wins at equal priority");
        }
    }

    @Test
    void inheritanceDecisionIsExplainable() {
        try (DriftService service = newService()) {
            service.publishBaselineSet(baseline(1, 1000));
            var result = service.submitSnapshot(new ConfigSnapshot("bd-1", Set.of("bigdata"), 1,
                    Instant.now(), Map.of("cache.max_memory", "1g")));
            String explanation = result.evaluation().violations().get(0).explanation();
            assertTrue(explanation.contains("candidate"), explanation);
            assertTrue(explanation.contains("WINNER"), explanation);
            assertTrue(explanation.contains("group:bigdata"), explanation);
        }
    }

    @Test
    void baselineUpdateResolvesDrift() {
        try (DriftService service = newService()) {
            service.publishBaselineSet(baseline(1, 1000));
            service.submitSnapshot(new ConfigSnapshot("plain-1", Set.of(), 1, Instant.now(),
                    Map.of("cache.max_memory", "1g")));
            assertEquals(1, service.findings("plain-1").size());

            // baseline updated to accept 1g globally
            service.publishBaselineSet(new BaselineSetVersion(2, List.of(
                    new BaselineEntry(Scope.global(), "cache.max_memory", "1g",
                            Severity.MEDIUM, 2000, 0)),
                    Instant.now()));
            assertEquals(FindingStatus.RESOLVED, service.findings("plain-1").get(0).status());
        }
    }
}
