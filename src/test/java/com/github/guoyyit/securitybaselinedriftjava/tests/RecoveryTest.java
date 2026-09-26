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
import com.github.guoyyit.securitybaselinedriftjava.store.journal.Journal;
import com.github.guoyyit.securitybaselinedriftjava.store.journal.JournalRecord;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

/** Crash recovery: replay from the last committed position, no duplicates, no torn writes. */
class RecoveryTest {

    @TempDir
    Path tempDir;

    private DriftService newService(Path journalFile) {
        DriftProperties props = new DriftProperties();
        props.setJournalDir(tempDir.toString());
        return new DriftService(props, journalFile);
    }

    private static RuleSetVersion rule() {
        return new RuleSetVersion(1, List.of(new Rule(
                "r-banner", "banner set", Scope.global(),
                "ssh.banner", Rule.Operator.EQUALS, "authorized-only", Severity.MEDIUM)),
                Instant.now());
    }

    private static ConfigSnapshot violating(long version) {
        return new ConfigSnapshot("node-1", Set.of(), version, Instant.now(),
                Map.of("ssh.banner", "welcome"));
    }

    @Test
    void restartRestoresCommittedStateWithoutDuplicates() {
        Path journalFile = tempDir.resolve("journal.log");
        List<Finding> before;
        try (DriftService service = newService(journalFile)) {
            service.publishRuleSet(rule());
            service.submitSnapshot(violating(1));
            service.submitSnapshot(violating(2)); // -> OPEN
            service.acknowledge(service.findings("node-1").get(0).fingerprint(), "oncall");
            before = service.allFindings();
        }

        try (DriftService recovered = newService(journalFile)) {
            recovered.recover();
            List<Finding> after = recovered.allFindings();
            assertEquals(before.size(), after.size(), "no duplicate or lost findings after restart");
            Finding restored = after.get(0);
            assertEquals(before.get(0).fingerprint(), restored.fingerprint());
            assertEquals(FindingStatus.ACKNOWLEDGED, restored.status(), "ack survives restart");
            assertEquals("oncall", restored.acknowledgedBy());
            assertEquals(2, recovered.latestSnapshot("node-1").orElseThrow().version());
            assertEquals(1, recovered.currentRuleSet().orElseThrow().version());
        }
    }

    @Test
    void crashBetweenSnapshotAndEvaluationIsReconciled() throws Exception {
        Path journalFile = tempDir.resolve("journal.log");
        // simulate a crash: snapshot committed to the journal, evaluation never committed
        try (Journal journal = new Journal(journalFile)) {
            journal.append(new JournalRecord.RuleSetCommitted(rule()));
            journal.append(new JournalRecord.SnapshotAccepted(violating(1)));
            // crash here: no EvaluationCommitted record
        }

        try (DriftService recovered = newService(journalFile)) {
            recovered.recover();
            List<Finding> findings = recovered.findings("node-1");
            assertEquals(1, findings.size(),
                    "reconcile after recovery must produce the finding that was never committed");
            assertEquals(FindingStatus.NEW, findings.get(0).status());
        }

        // a second recovery must not duplicate anything
        try (DriftService recoveredAgain = newService(journalFile)) {
            recoveredAgain.recover();
            assertEquals(1, recoveredAgain.findings("node-1").size(),
                    "recovery is idempotent: no duplicate findings");
        }
    }

    @Test
    void tornTailIsDiscardedOnRecovery() throws Exception {
        Path journalFile = tempDir.resolve("journal.log");
        try (DriftService service = newService(journalFile)) {
            service.publishRuleSet(rule());
            service.submitSnapshot(violating(1));
        }
        long committedSize = Files.size(journalFile);

        // simulate a torn write: half of a record appended before power loss
        Files.write(journalFile, new byte[]{0, 0, 0, 100, 1, 2}, StandardOpenOption.APPEND);

        try (DriftService recovered = newService(journalFile)) {
            recovered.recover();
            assertEquals(1, recovered.findings("node-1").size(),
                    "committed records survive; torn tail is discarded");
            assertEquals(FindingStatus.NEW, recovered.findings("node-1").get(0).status());
        }
        // journal truncated back to the committed boundary
        assertEquals(committedSize, Files.size(journalFile));

        // and the service keeps working on the cleaned journal
        try (DriftService continued = newService(journalFile)) {
            continued.recover();
            continued.submitSnapshot(new ConfigSnapshot("node-1", Set.of(), 2, Instant.now(),
                    Map.of("ssh.banner", "authorized-only")));
            assertEquals(FindingStatus.RESOLVED, continued.findings("node-1").get(0).status());
        }
    }

    @Test
    void evaluationIdsContinueMonotonicallyAfterRecovery() {
        Path journalFile = tempDir.resolve("journal.log");
        long lastEvalId;
        try (DriftService service = newService(journalFile)) {
            service.publishRuleSet(rule());
            lastEvalId = service.submitSnapshot(violating(1)).evaluation().evalId();
        }
        try (DriftService recovered = newService(journalFile)) {
            recovered.recover();
            var result = recovered.submitSnapshot(violating(2));
            assertTrue(result.evaluation().evalId() > lastEvalId,
                    "eval ids must not restart from zero after recovery");
        }
    }
}
