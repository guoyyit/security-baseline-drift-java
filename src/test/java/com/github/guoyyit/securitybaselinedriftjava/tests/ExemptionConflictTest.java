package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.config.DriftProperties;
import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.Exemption;
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
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Exemption conflicts resolve by scope specificity, then latest created; expired ones never apply. */
class ExemptionConflictTest {

    @TempDir
    Path tempDir;

    private DriftService newService() {
        DriftProperties props = new DriftProperties();
        props.setJournalDir(tempDir.toString());
        return new DriftService(props, tempDir.resolve("journal.log"));
    }

    private static RuleSetVersion tlsRule() {
        return new RuleSetVersion(1, List.of(new Rule(
                "r-tls", "tls version", Scope.global(),
                "net.tls_version", Rule.Operator.EQUALS, "TLSv1.3", Severity.HIGH)),
                Instant.now());
    }

    private static ConfigSnapshot violatingSnapshot(String source, Set<String> groups) {
        return new ConfigSnapshot(source, groups, 1, Instant.now(),
                Map.of("net.tls_version", "TLSv1.0"));
    }

    private static Exemption exemption(String id, Scope scope, Instant createdAt, Instant expiresAt) {
        return new Exemption(id, "r-tls", "net.tls_version", scope,
                "migration in progress", "security-team", createdAt, expiresAt);
    }

    @Test
    void moreSpecificScopeWinsConflict() {
        try (DriftService service = newService()) {
            service.publishRuleSet(tlsRule());
            Instant now = Instant.now();
            // global exemption created later, source exemption created earlier:
            // specificity beats recency
            service.addExemption(exemption("ex-source", Scope.source("web-1"),
                    now, now.plus(1, ChronoUnit.DAYS)));
            service.addExemption(exemption("ex-global", Scope.global(),
                    now.plus(1, ChronoUnit.MINUTES), now.plus(1, ChronoUnit.DAYS)));

            service.submitSnapshot(violatingSnapshot("web-1", Set.of()));
            var finding = service.findings("web-1").get(0);
            assertEquals(FindingStatus.SUPPRESSED, finding.status());
            assertEquals("ex-source", finding.suppressedByExemptionId(),
                    "source-scoped exemption must win over the global one");
        }
    }

    @Test
    void expiredExemptionDoesNotApply() {
        try (DriftService service = newService()) {
            service.publishRuleSet(tlsRule());
            Instant now = Instant.now();
            service.addExemption(exemption("ex-expired", Scope.global(),
                    now.minus(2, ChronoUnit.DAYS), now.minus(1, ChronoUnit.DAYS)));

            service.submitSnapshot(violatingSnapshot("web-1", Set.of()));
            var finding = service.findings("web-1").get(0);
            assertEquals(FindingStatus.NEW, finding.status(), "expired exemption must not suppress");
        }
    }

    @Test
    void removingExemptionReactivatesFinding() {
        try (DriftService service = newService()) {
            service.publishRuleSet(tlsRule());
            Instant now = Instant.now();
            service.addExemption(exemption("ex-1", Scope.global(), now, now.plus(1, ChronoUnit.DAYS)));
            service.submitSnapshot(violatingSnapshot("web-1", Set.of()));
            assertEquals(FindingStatus.SUPPRESSED, service.findings("web-1").get(0).status());

            service.removeExemption("ex-1");
            var finding = service.findings("web-1").get(0);
            assertEquals(FindingStatus.OPEN, finding.status(),
                    "finding must become active again once the exemption is removed");
            assertEquals(1, service.findings("web-1").size(), "still the same single finding");
        }
    }

    @Test
    void groupScopeAppliesToMemberSourcesOnly() {
        try (DriftService service = newService()) {
            service.publishRuleSet(tlsRule());
            Instant now = Instant.now();
            service.addExemption(exemption("ex-group", Scope.group("legacy"),
                    now, now.plus(1, ChronoUnit.DAYS)));

            service.submitSnapshot(violatingSnapshot("web-1", Set.of("legacy")));
            service.submitSnapshot(violatingSnapshot("web-2", Set.of("modern")));

            assertEquals(FindingStatus.SUPPRESSED, service.findings("web-1").get(0).status());
            assertEquals(FindingStatus.NEW, service.findings("web-2").get(0).status(),
                    "exemption scoped to group 'legacy' must not cover 'modern' sources");
        }
    }

    @Test
    void conflictDecisionIsExplainable() {
        try (DriftService service = newService()) {
            service.publishRuleSet(tlsRule());
            Instant now = Instant.now();
            service.addExemption(exemption("ex-a", Scope.global(), now, now.plus(1, ChronoUnit.DAYS)));
            service.addExemption(exemption("ex-b", Scope.source("web-1"),
                    now, now.plus(1, ChronoUnit.DAYS)));
            var result = service.submitSnapshot(violatingSnapshot("web-1", Set.of()));
            String explanation = result.evaluation().violations().get(0).explanation();
            assertTrue(explanation.contains("ex-b"), explanation);
            assertTrue(explanation.contains("conflict resolved"), explanation);
            assertTrue(explanation.contains("WINNER"), explanation);
        }
    }
}
