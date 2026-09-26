package com.github.guoyyit.securitybaselinedriftjava.model;

import java.util.List;

/**
 * Result of checking one source's latest snapshot against one complete
 * rule-set version + baseline-set version + exemption-set version.
 */
public record CheckReport(String sourceId,
                          long snapshotVersion,
                          long ruleSetVersion,
                          long baselineSetVersion,
                          long exemptionVersion,
                          List<Violation> violations,
                          List<String> explanations,
                          boolean fromCache) {
    public CheckReport {
        violations = List.copyOf(violations);
        explanations = List.copyOf(explanations);
    }
}
