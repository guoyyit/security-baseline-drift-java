package com.github.guoyyit.securitybaselinedriftjava.domain;

import java.util.Objects;

/**
 * A raw violation produced by one evaluation pass, before lifecycle/dedup
 * handling in the finding store.
 */
public record Violation(
        String sourceId,
        String ruleId,
        String configKey,
        Scope scope,
        Severity severity,
        String expectedValue,
        String actualValue,
        String explanation) {

    public Violation {
        Objects.requireNonNull(sourceId, "sourceId");
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(configKey, "configKey");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(severity, "severity");
    }

    public String fingerprint() {
        return Finding.fingerprintOf(sourceId, ruleId, configKey);
    }
}
