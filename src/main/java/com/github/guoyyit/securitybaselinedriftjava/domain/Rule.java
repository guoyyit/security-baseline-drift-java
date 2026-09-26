package com.github.guoyyit.securitybaselinedriftjava.domain;

import java.util.Objects;

/**
 * A single compliance rule: within {@link #scope}, config key {@link #configKey}
 * must satisfy {@link #operator} against {@link #expectedValue}.
 */
public record Rule(
        String ruleId,
        String description,
        Scope scope,
        String configKey,
        Operator operator,
        String expectedValue,
        Severity severity) {

    public enum Operator {
        EQUALS,
        NOT_EQUALS,
        IN,
        NOT_IN,
        REGEX,
        GT,
        GTE,
        LT,
        LTE,
        EXISTS,
        ABSENT
    }

    public Rule {
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(configKey, "configKey");
        Objects.requireNonNull(operator, "operator");
        Objects.requireNonNull(severity, "severity");
    }
}
