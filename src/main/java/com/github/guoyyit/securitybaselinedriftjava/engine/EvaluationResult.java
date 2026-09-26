package com.github.guoyyit.securitybaselinedriftjava.engine;

import com.github.guoyyit.securitybaselinedriftjava.domain.Finding;
import com.github.guoyyit.securitybaselinedriftjava.domain.Violation;

import java.util.List;

/**
 * Outcome of evaluating one source.
 *
 * @param evalId          monotonic evaluation id
 * @param sourceId        evaluated source
 * @param snapshotVersion snapshot version evaluated
 * @param ruleSetVersion  rule set version used
 * @param baselineVersion baseline set version used
 * @param violations      raw violations detected (before lifecycle handling)
 * @param upserted        findings after lifecycle transitions (empty if none changed)
 * @param fromCache       true if the result was served from the incremental cache
 */
public record EvaluationResult(
        long evalId,
        String sourceId,
        long snapshotVersion,
        long ruleSetVersion,
        long baselineVersion,
        List<Violation> violations,
        List<Finding> upserted,
        boolean fromCache) {

    public EvaluationResult {
        violations = List.copyOf(violations);
        upserted = List.copyOf(upserted);
    }
}
