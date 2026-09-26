package com.github.guoyyit.securitybaselinedriftjava.model;

import java.time.Instant;

/**
 * An exemption waiving a rule ("*" = all rules) within a scope.
 * Conflict resolution: higher priority wins; ties broken by scope specificity, then by id.
 */
public record Exemption(String id,
                        String ruleId,
                        Scope scope,
                        String reason,
                        int priority,
                        Instant expiresAt) {

    public boolean isActive(Instant now) {
        return expiresAt == null || now.isBefore(expiresAt);
    }

    public boolean covers(String rule, String sourceId) {
        return ("*".equals(ruleId) || ruleId.equals(rule)) && scope.matches(sourceId);
    }
}
