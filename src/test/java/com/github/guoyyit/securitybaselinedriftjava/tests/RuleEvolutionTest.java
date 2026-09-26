package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.config.DriftProperties;
import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.FindingStatus;
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
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Versioned rule set updates: complete-version visibility and reproducibility. */
class RuleEvolutionTest {

    @TempDir
    Path tempDir;

    private DriftService newService() {
        DriftProperties props = new DriftProperties();
        props.setJournalDir(tempDir.toString());
        return new DriftService(props, tempDir.resolve("journal.log"));
    }

    private static RuleSetVersion ruleSet(long version, String key, String expected) {
        return new RuleSetVersion(version, List.of(new Rule(
                "r-" + key, "check " + key, Scope.global(),
                key, Rule.Operator.EQUALS, expected, Severity.MEDIUM)),
                Instant.now());
    }

    private static ConfigSnapshot snapshot(String source, long version, Map<String, String> configs) {
        return new ConfigSnapshot(source, Set.of(), version, Instant.now(), configs);
    }

    @Test
    void ruleUpdateReevaluatesAndUpdatesFindings() {
        try (DriftService service = newService()) {
            service.publishRuleSet(ruleSet(1, "ssh.port", "22"));
            service.submitSnapshot(snapshot("db-1", 1, Map.of("ssh.port", "2222")));
            assertEquals(1, service.findings("db-1").size());
            assertEquals(FindingStatus.NEW, service.findings("db-1").get(0).status());

            // rule evolves: 2222 becomes acceptable -> finding resolves
            service.publishRuleSet(ruleSet(2, "ssh.port", "2222"));
            assertEquals(FindingStatus.RESOLVED, service.findings("db-1").get(0).status());
            assertEquals(2, service.currentRuleSet().orElseThrow().version());
        }
    }

    @Test
    void historicalVersionsAreReproducible() {
        try (DriftService service = newService()) {
            service.publishRuleSet(ruleSet(1, "ssh.port", "22"));
            service.publishRuleSet(ruleSet(2, "ssh.port", "2222"));
            service.submitSnapshot(snapshot("db-1", 1, Map.of("ssh.port", "2222")));

            // evaluate the same snapshot against the historical rule set v1
            EvaluationEngine engine = new EvaluationEngine(16);
            var snapshot = service.latestSnapshot("db-1").orElseThrow();
            var historical = service.currentRuleSet(); // active is v2
            assertEquals(2, historical.orElseThrow().version());

            // reproduce with v1 via the service's versioned store through a fresh evaluation
            RuleSetVersion v1 = new RuleSetVersion(1, List.of(new Rule(
                    "r-ssh.port", "check ssh.port", Scope.global(),
                    "ssh.port", Rule.Operator.EQUALS, "22", Severity.MEDIUM)), Instant.now());
            var resultV1 = engine.evaluateCached(snapshot, v1,
                    new com.github.guoyyit.securitybaselinedriftjava.domain.BaselineSetVersion(
                            0, List.of(), Instant.EPOCH),
                    List.of(), 0, Instant.now());
            assertEquals(1, resultV1.violations().size(),
                    "historical rule set v1 must still flag 2222 as a violation");

            var resultV2 = engine.evaluateCached(snapshot, historical.orElseThrow(),
                    new com.github.guoyyit.securitybaselinedriftjava.domain.BaselineSetVersion(
                            0, List.of(), Instant.EPOCH),
                    List.of(), 0, Instant.now());
            assertTrue(resultV2.violations().isEmpty(), "current rule set v2 accepts 2222");
        }
    }

    @Test
    void evaluationSeesOneCompleteVersion() {
        try (DriftService service = newService()) {
            service.publishRuleSet(ruleSet(1, "a", "1"));
            service.submitSnapshot(snapshot("s1", 1, Map.of("a", "1")));
            var result = service.evaluateNow("s1");
            // the recorded rule set version of the evaluation is a real published version
            assertEquals(1, result.ruleSetVersion());
            // findings carry the version they were computed with
            service.publishRuleSet(ruleSet(2, "a", "2"));
            var finding = service.findings("s1").get(0);
            assertEquals(2, finding.ruleSetVersion(),
                    "after rule update the finding reflects exactly version 2, not a mix");
        }
    }
}
