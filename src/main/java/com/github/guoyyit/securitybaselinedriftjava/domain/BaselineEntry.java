package com.github.guoyyit.securitybaselinedriftjava.domain;

import java.util.Objects;

/**
 * One baseline expectation: within {@link #scope}, config {@link #configKey}
 * should equal {@link #expectedValue}. Baselines express inheritance: a SOURCE
 * scoped entry overrides a GROUP scoped one, which overrides GLOBAL.
 */
public record BaselineEntry(
        Scope scope,
        String configKey,
        String expectedValue,
        Severity severity,
        long updatedAtMillis,
        long priority) {

    public BaselineEntry {
        Objects.requireNonNull(scope, "scope");
        Objects.requireNonNull(configKey, "configKey");
        Objects.requireNonNull(expectedValue, "expectedValue");
        severity = severity == null ? Severity.MEDIUM : severity;
    }
}
