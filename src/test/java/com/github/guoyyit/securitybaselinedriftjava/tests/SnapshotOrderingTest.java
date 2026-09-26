package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.config.DriftProperties;
import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.FindingStatus;
import com.github.guoyyit.securitybaselinedriftjava.domain.Rule;
import com.github.guoyyit.securitybaselinedriftjava.domain.RuleSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.Scope;
import com.github.guoyyit.securitybaselinedriftjava.domain.Severity;
import com.github.guoyyit.securitybaselinedriftjava.service.DriftService;
import com.github.guoyyit.securitybaselinedriftjava.store.SnapshotStore;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Out-of-order, duplicate and late snapshots must not skew the final verdict. */
class SnapshotOrderingTest {

    @TempDir
    Path tempDir;

    private DriftService newService() {
        DriftProperties props = new DriftProperties();
        props.setJournalDir(tempDir.toString());
        return new DriftService(props, tempDir.resolve("journal.log"));
    }

    private static ConfigSnapshot snapshot(String source, long version, Map<String, String> configs) {
        return new ConfigSnapshot(source, Set.of(), version, Instant.now(), configs);
    }

    private static RuleSetVersion passwordRule(long version, String expected) {
        return new RuleSetVersion(version, List.of(new Rule(
                "r-password-length", "password min length", Scope.global(),
                "auth.min_password_length", Rule.Operator.EQUALS, expected, Severity.HIGH)),
                Instant.now());
    }

    @Test
    void outOfOrderSnapshotDoesNotChangeFinalVerdict() {
        try (DriftService service = newService()) {
            service.publishRuleSet(passwordRule(1, "12"));

            // newest arrives first
            var r2 = service.submitSnapshot(snapshot("web-1", 2, Map.of("auth.min_password_length", "12")));
            assertEquals(SnapshotStore.AcceptResult.ACCEPTED, r2.acceptResult());
            assertTrue(r2.evaluation().violations().isEmpty(), "v2 is compliant");

            // older snapshot arrives late: must be rejected and change nothing
            var r1 = service.submitSnapshot(snapshot("web-1", 1, Map.of("auth.min_password_length", "6")));
            assertEquals(SnapshotStore.AcceptResult.DUPLICATE_OR_STALE, r1.acceptResult());
            assertNull(r1.evaluation());

            assertEquals(2, service.latestSnapshot("web-1").orElseThrow().version());
            assertTrue(service.findings("web-1").stream().noneMatch(f -> f.status() == FindingStatus.OPEN),
                    "final verdict must reflect the latest (compliant) state");
        }
    }

    @Test
    void duplicateSnapshotIsIdempotent() {
        try (DriftService service = newService()) {
            service.publishRuleSet(passwordRule(1, "12"));
            var first = service.submitSnapshot(snapshot("web-1", 1, Map.of("auth.min_password_length", "6")));
            assertEquals(SnapshotStore.AcceptResult.ACCEPTED, first.acceptResult());
            assertEquals(1, first.evaluation().violations().size());

            var dup = service.submitSnapshot(snapshot("web-1", 1, Map.of("auth.min_password_length", "6")));
            assertEquals(SnapshotStore.AcceptResult.DUPLICATE_OR_STALE, dup.acceptResult());

            // exactly one finding exists; no duplicate generated
            assertEquals(1, service.findings("web-1").size());
        }
    }

    @Test
    void lateArrivalAfterFixDoesNotReopenFinding() {
        try (DriftService service = newService()) {
            service.publishRuleSet(passwordRule(1, "12"));
            service.submitSnapshot(snapshot("web-1", 1, Map.of("auth.min_password_length", "6")));
            assertEquals(1, service.findings("web-1").size());

            // fix arrives (v2), then the stale violating v1 arrives late
            service.submitSnapshot(snapshot("web-1", 2, Map.of("auth.min_password_length", "12")));
            assertEquals(FindingStatus.RESOLVED, service.findings("web-1").get(0).status());

            service.submitSnapshot(snapshot("web-1", 1, Map.of("auth.min_password_length", "6")));
            assertEquals(FindingStatus.RESOLVED, service.findings("web-1").get(0).status(),
                    "late violating snapshot must not reopen the resolved finding");
        }
    }
}
