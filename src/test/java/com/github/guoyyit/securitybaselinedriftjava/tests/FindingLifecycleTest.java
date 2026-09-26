package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.config.DriftProperties;
import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.Finding;
import com.github.guoyyit.securitybaselinedriftjava.domain.FindingStatus;
import com.github.guoyyit.securitybaselinedriftjava.domain.Rule;
import com.github.guoyyit.securitybaselinedriftjava.domain.RuleSetVersion;
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

/** Finding lifecycle: NEW -> OPEN -> ACKNOWLEDGED -> RESOLVED -> reopened. */
class FindingLifecycleTest {

    @TempDir
    Path tempDir;

    private DriftService newService() {
        DriftProperties props = new DriftProperties();
        props.setJournalDir(tempDir.toString());
        return new DriftService(props, tempDir.resolve("journal.log"));
    }

    private static RuleSetVersion rule() {
        return new RuleSetVersion(1, List.of(new Rule(
                "r-root-login", "root login disabled", Scope.global(),
                "ssh.permit_root_login", Rule.Operator.EQUALS, "no", Severity.CRITICAL)),
                Instant.now());
    }

    private static ConfigSnapshot snapshot(long version, String rootLogin) {
        return new ConfigSnapshot("node-1", Set.of(), version, Instant.now(),
                Map.of("ssh.permit_root_login", rootLogin));
    }

    @Test
    void fullLifecycleWithDeduplication() {
        try (DriftService service = newService()) {
            service.publishRuleSet(rule());

            // 1. first violation -> NEW
            service.submitSnapshot(snapshot(1, "yes"));
            Finding f = service.findings("node-1").get(0);
            assertEquals(FindingStatus.NEW, f.status());
            String fingerprint = f.fingerprint();

            // 2. violation persists -> OPEN (持续), still a single finding
            service.submitSnapshot(snapshot(2, "yes"));
            f = service.findings("node-1").get(0);
            assertEquals(FindingStatus.OPEN, f.status());
            assertEquals(fingerprint, f.fingerprint(), "deduplicated by fingerprint");
            assertEquals(1, service.findings("node-1").size());

            // 3. manual acknowledgement
            service.acknowledge(fingerprint, "oncall-alice");
            f = service.findings("node-1").get(0);
            assertEquals(FindingStatus.ACKNOWLEDGED, f.status());
            assertEquals("oncall-alice", f.acknowledgedBy());

            // 4. risk fixed -> RESOLVED (解除)
            service.submitSnapshot(snapshot(3, "no"));
            f = service.findings("node-1").get(0);
            assertEquals(FindingStatus.RESOLVED, f.status());
            assertTrue(f.resolvedAt() != null);

            // 5. compliant re-evaluation must NOT re-alert
            service.submitSnapshot(snapshot(4, "no"));
            assertEquals(1, service.findings("node-1").size());
            assertEquals(FindingStatus.RESOLVED, service.findings("node-1").get(0).status());

            // 6. violation reappears -> reopened on the SAME finding, not a new one
            service.submitSnapshot(snapshot(5, "yes"));
            List<Finding> findings = service.findings("node-1");
            assertEquals(1, findings.size(), "reopen must not create a duplicate finding");
            assertEquals(FindingStatus.OPEN, findings.get(0).status());
            assertEquals(fingerprint, findings.get(0).fingerprint());
            assertTrue(findings.get(0).firstSeenEvalId() < findings.get(0).lastSeenEvalId(),
                    "history is preserved across the reopen");
        }
    }

    @Test
    void acknowledgedFindingStaysAcknowledgedWhileViolationPersists() {
        try (DriftService service = newService()) {
            service.publishRuleSet(rule());
            service.submitSnapshot(snapshot(1, "yes"));
            String fingerprint = service.findings("node-1").get(0).fingerprint();
            service.acknowledge(fingerprint, "oncall-bob");

            service.submitSnapshot(snapshot(2, "yes"));
            assertEquals(FindingStatus.ACKNOWLEDGED, service.findings("node-1").get(0).status());
        }
    }
}
