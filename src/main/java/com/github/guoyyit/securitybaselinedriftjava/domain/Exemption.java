package com.github.guoyyit.securitybaselinedriftjava.domain;

import java.time.Instant;
import java.util.Objects;

/**
 * An exemption waives a rule (or a baseline check on a key) within a scope until
 * {@link #expiresAt}. Conflicts between matching exemptions are resolved by scope
 * specificity, then by the later {@link #createdAt}, and the decision is explainable.
 */
public record Exemption(
        String exemptionId,
        String ruleId,
        String configKey,
        Scope scope,
        String reason,
        String approvedBy,
        Instant createdAt,
        Instant expiresAt) {

    public Exemption {
        Objects.requireNonNull(exemptionId, "exemptionId");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(createdAt, "createdAt");
        // expiresAt may be null meaning "never expires"
    }

    public boolean isActive(Instant now) {
        return expiresAt == null || now.isBefore(expiresAt);
    }
}
