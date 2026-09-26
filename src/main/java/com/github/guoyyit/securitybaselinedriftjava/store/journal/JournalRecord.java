package com.github.guoyyit.securitybaselinedriftjava.store.journal;

import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.Exemption;
import com.github.guoyyit.securitybaselinedriftjava.domain.Finding;
import com.github.guoyyit.securitybaselinedriftjava.domain.RuleSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.BaselineSetVersion;

import java.util.List;

/**
 * One atomic entry in the write-ahead journal. Every state mutation is journaled
 * before (or as) it is applied; recovery replays records in LSN order.
 */
public sealed interface JournalRecord {

    /** A snapshot was accepted as the latest state of its source. */
    record SnapshotAccepted(ConfigSnapshot snapshot) implements JournalRecord {
    }

    /** A new immutable rule set version became active. */
    record RuleSetCommitted(RuleSetVersion ruleSet) implements JournalRecord {
    }

    /** A new immutable baseline set version became active. */
    record BaselineSetCommitted(BaselineSetVersion baselineSet) implements JournalRecord {
    }

    /** An exemption was added. */
    record ExemptionAdded(Exemption exemption) implements JournalRecord {
    }

    /** An exemption was removed by id. */
    record ExemptionRemoved(String exemptionId) implements JournalRecord {
    }

    /** A finding was manually acknowledged by an operator. */
    record FindingAcknowledged(String fingerprint, String operator) implements JournalRecord {
    }

    /**
     * The finding transitions of one evaluation, committed atomically: either the
     * whole record is replayed or none of it, so a crash can never leave
     * partially written findings.
     *
     * @param evalId           monotonic evaluation id
     * @param sourceId         evaluated source
     * @param snapshotVersion  snapshot version the evaluation ran against
     * @param ruleSetVersion   rule set version used
     * @param baselineVersion  baseline set version used
     * @param exemptionVersion exemption set version used
     * @param upserted         findings after transition, keyed by fingerprint
     */
    record EvaluationCommitted(
            long evalId,
            String sourceId,
            long snapshotVersion,
            long ruleSetVersion,
            long baselineVersion,
            long exemptionVersion,
            List<Finding> upserted) implements JournalRecord {
        public EvaluationCommitted {
            upserted = List.copyOf(upserted);
        }
    }
}
