package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.config.ServiceProperties;
import com.github.guoyyit.securitybaselinedriftjava.engine.CheckEngine;
import com.github.guoyyit.securitybaselinedriftjava.engine.ScopeResolver;
import com.github.guoyyit.securitybaselinedriftjava.model.Baseline;
import com.github.guoyyit.securitybaselinedriftjava.model.CheckReport;
import com.github.guoyyit.securitybaselinedriftjava.model.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.model.Exemption;
import com.github.guoyyit.securitybaselinedriftjava.model.Finding;
import com.github.guoyyit.securitybaselinedriftjava.model.FindingStatus;
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

import static org.junit.jupiter.api.Assertions.*;

class DriftDetectionServiceTest {

    @TempDir
    Path checkpointDir;

    private DriftDetectionService newService() {
        ServiceProperties props = new ServiceProperties();
        props.setCheckpointDir(checkpointDir.toString());
        props.setCacheMaxEntries(64);
        return new DriftDetectionService(
                new SnapshotStore(), new RuleSetStore(), new BaselineStore(),
                new ExemptionStore(), new FindingStore(),
                new CheckEngine(new ScopeResolver()), props);
    }

    private static Rule passwordRule(String expected) {
        return new Rule("pwd-policy", Scope.global(), "password.min.length",
                Operator.EQUALS, expected, Severity.HIGH, "password policy mismatch");
    }

    private static ConfigSnapshot snap(String source, long version, Map<String, String> attrs) {
        return new ConfigSnapshot(source, version, Instant.now(), attrs);
    }

    @Test
    void ruleEvolutionKeepsVersionsConsistentAndReproducible() {
        DriftDetectionService svc = newService();
        long v1 = svc.publishRules(List.of(passwordRule("12")));
        svc.submitSnapshot(snap("host-1", 1, Map.of("password.min.length", "8")));

        List<Finding> findings = svc.findings(Optional.empty());
        assertEquals(1, findings.size());
        assertEquals(v1, findings.get(0).getRuleSetVersion());
        assertEquals(FindingStatus.NEW, findings.get(0).getStatus());

        // Rule evolves: 8 becomes compliant -> finding resolves on the new complete version.
        long v2 = svc.publishRules(List.of(passwordRule("8")));
        findings = svc.findings(Optional.empty());
        assertEquals(1, findings.size());
        assertEquals(FindingStatus.RESOLVED, findings.get(0).getStatus());
        assertEquals(2, v2);
    }

    @Test
    void findingLifecycleNewPersistentResolvedReopen() {
        DriftDetectionService svc = newService();
        svc.publishRules(List.of(passwordRule("12")));
        svc.submitSnapshot(snap("host-1", 1, Map.of("password.min.length", "8")));
        String fp = Finding.fingerprint("pwd-policy", "host-1", "password.min.length");

        assertEquals(FindingStatus.NEW, svc.findings(Optional.empty()).get(0).getStatus());

        // Still violating in a later check -> PERSISTENT.
        svc.submitSnapshot(snap("host-1", 2, Map.of("password.min.length", "8")));
        assertEquals(FindingStatus.PERSISTENT, svc.findings(Optional.empty()).get(0).getStatus());

        // Risk fixed -> RESOLVED.
        svc.submitSnapshot(snap("host-1", 3, Map.of("password.min.length", "12")));
        Finding resolved = svc.findings(Optional.empty()).get(0);
        assertEquals(FindingStatus.RESOLVED, resolved.getStatus());
        assertNotNull(resolved.getResolvedAt());

        // Repeated clean checks must not re-alert or duplicate.
        svc.submitSnapshot(snap("host-1", 4, Map.of("password.min.length", "12")));
        svc.checkAll();
        List<Finding> all = svc.findings(Optional.empty());
        assertEquals(1, all.size());
        assertEquals(FindingStatus.RESOLVED, all.get(0).getStatus());

        // Regression -> same finding reopens as NEW, still no duplicate.
        svc.submitSnapshot(snap("host-1", 5, Map.of("password.min.length", "8")));
        all = svc.findings(Optional.empty());
        assertEquals(1, all.size());
        assertEquals(fp, all.get(0).getFingerprint());
        assertEquals(FindingStatus.NEW, all.get(0).getStatus());
    }

    @Test
    void acknowledgeIsManualOverlay() {
        DriftDetectionService svc = newService();
        svc.publishRules(List.of(passwordRule("12")));
        svc.submitSnapshot(snap("host-1", 1, Map.of("password.min.length", "8")));
        String fp = svc.findings(Optional.empty()).get(0).getFingerprint();

        assertTrue(svc.acknowledge(fp).isPresent());
        assertEquals(FindingStatus.ACKNOWLEDGED, svc.findings(Optional.empty()).get(0).getStatus());
        assertTrue(svc.acknowledge("nonexistent").isEmpty());
    }

    @Test
    void incrementalCheckUsesCacheAndInvalidatesOnChange() {
        DriftDetectionService svc = newService();
        svc.publishRules(List.of(passwordRule("12")));
        svc.submitSnapshot(snap("host-1", 1, Map.of("password.min.length", "8")));

        // Unchanged snapshot + unchanged rules -> served from cache, not re-evaluated.
        CheckReport second = svc.checkSource("host-1");
        assertTrue(second.fromCache());
        assertEquals(1, second.violations().size());

        // Rule change invalidates naturally (new version in key): publishRules already
        // re-evaluated, so the hit below must return the NEW generation's result,
        // never the stale v1 violations.
        svc.publishRules(List.of(passwordRule("8")));
        CheckReport third = svc.checkSource("host-1");
        assertEquals(2, third.ruleSetVersion());
        assertEquals(0, third.violations().size()); // "8" is compliant under the new rule

        // Changed snapshot content is re-evaluated correctly (new key, no stale data).
        svc.submitSnapshot(snap("host-1", 2, Map.of("password.min.length", "6")));
        CheckReport fourth = svc.checkSource("host-1");
        assertEquals(1, fourth.violations().size());
    }

    @Test
    void boundedCacheEvictsAndMisses() {
        ServiceProperties props = new ServiceProperties();
        props.setCheckpointDir(checkpointDir.resolve("tiny-cache").toString());
        props.setCacheMaxEntries(1);
        DriftDetectionService svc = new DriftDetectionService(
                new SnapshotStore(), new RuleSetStore(), new BaselineStore(),
                new ExemptionStore(), new FindingStore(),
                new CheckEngine(new ScopeResolver()), props);
        svc.publishRules(List.of(passwordRule("12")));
        svc.submitSnapshot(snap("host-1", 1, Map.of("password.min.length", "8")));
        svc.submitSnapshot(snap("host-2", 1, Map.of("password.min.length", "8")));
        // host-1's entry was evicted (max 1 entry). host-2 is still cached -> hit;
        // checking host-1 afterwards is a genuine miss (and evicts host-2).
        assertTrue(svc.checkSource("host-2").fromCache());
        assertFalse(svc.checkSource("host-1").fromCache());
    }

    @Test
    void exemptionWaivesViolationEndToEnd() {
        DriftDetectionService svc = newService();
        svc.publishRules(List.of(passwordRule("12")));
        svc.replaceExemptions(List.of(
                new Exemption("ex-1", "pwd-policy", Scope.exact("host-1"), "legacy system", 10, null)));
        svc.submitSnapshot(snap("host-1", 1, Map.of("password.min.length", "8")));
        assertEquals(0, svc.findings(Optional.empty()).size());

        // Exemption removed -> violation appears.
        svc.replaceExemptions(List.of());
        assertEquals(1, svc.findings(Optional.empty()).size());
    }

    @Test
    void baselineDriftDetectedAndResolved() {
        DriftDetectionService svc = newService();
        svc.publishBaselines(List.of(
                new Baseline("base", Scope.global(), Map.of("tls.version", "1.3"))));
        svc.submitSnapshot(snap("host-1", 1, Map.of("tls.version", "1.0")));
        List<Finding> findings = svc.findings(Optional.empty());
        assertEquals(1, findings.size());
        assertTrue(findings.get(0).getRuleId().startsWith("baseline-drift:"));

        svc.submitSnapshot(snap("host-1", 2, Map.of("tls.version", "1.3")));
        assertEquals(FindingStatus.RESOLVED, svc.findings(Optional.empty()).get(0).getStatus());
    }

    @Test
    void crashRecoveryResumesFromLastCommittedPosition() {
        DriftDetectionService svcA = newService();
        svcA.publishRules(List.of(passwordRule("12")));
        svcA.submitSnapshot(snap("host-1", 1, Map.of("password.min.length", "8")));
        svcA.submitSnapshot(snap("host-2", 1, Map.of("password.min.length", "12")));
        long seqBefore = svcA.committedSequence();
        List<Finding> findingsBefore = svcA.findings(Optional.empty());
        assertTrue(seqBefore > 0);

        // Simulate crash + restart: brand-new stores, same checkpoint directory.
        DriftDetectionService svcB = newService();
        assertEquals(seqBefore, svcB.committedSequence());
        List<Finding> findingsAfter = svcB.findings(Optional.empty());
        assertEquals(findingsBefore.size(), findingsAfter.size());
        assertEquals(findingsBefore.stream().map(Finding::getFingerprint).sorted().toList(),
                findingsAfter.stream().map(Finding::getFingerprint).sorted().toList());
        assertEquals(findingsBefore.get(0).getStatus(), findingsAfter.get(0).getStatus());

        // Continue after recovery: no duplicated or lost findings.
        svcB.submitSnapshot(snap("host-1", 2, Map.of("password.min.length", "12")));
        List<Finding> continued = svcB.findings(Optional.empty());
        assertEquals(1, continued.size());
        assertEquals(FindingStatus.RESOLVED, continued.get(0).getStatus());
        assertTrue(svcB.committedSequence() > seqBefore);
    }

    @Test
    void outOfOrderSnapshotsDoNotChangeFinalCompliance() {
        DriftDetectionService svc = newService();
        svc.publishRules(List.of(passwordRule("12")));
        svc.submitSnapshot(snap("host-1", 3, Map.of("password.min.length", "12"))); // newest: compliant
        svc.submitSnapshot(snap("host-1", 1, Map.of("password.min.length", "8")));  // late: violating
        svc.submitSnapshot(snap("host-1", 3, Map.of("password.min.length", "12"))); // duplicate

        // Final judgement must reflect the newest (compliant) snapshot only.
        assertEquals(0, svc.findings(Optional.empty()).stream()
                .filter(f -> f.getStatus() != FindingStatus.RESOLVED).count());
    }
}
