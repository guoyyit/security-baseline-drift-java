package com.github.guoyyit.securitybaselinedriftjava.engine;

import com.github.guoyyit.securitybaselinedriftjava.domain.Violation;

/**
 * A violation together with the exemption decision: non-null
 * {@link #suppressedByExemptionId} means the violation is waived by that
 * exemption. The human-readable reasoning is carried in
 * {@link Violation#explanation()}.
 */
public record EvaluatedViolation(Violation violation, String suppressedByExemptionId) {
}
