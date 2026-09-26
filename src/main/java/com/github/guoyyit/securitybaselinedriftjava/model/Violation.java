package com.github.guoyyit.securitybaselinedriftjava.model;

/** One breached rule for one source, with a human-readable explanation. */
public record Violation(String ruleId,
                        String attributeKey,
                        String expected,
                        String actual,
                        Severity severity,
                        String explanation) {
}
