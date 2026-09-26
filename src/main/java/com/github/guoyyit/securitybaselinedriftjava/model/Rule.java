package com.github.guoyyit.securitybaselinedriftjava.model;

/** A single compliance rule: within scope, attribute must satisfy operator/expectedValue. */
public record Rule(String id,
                   Scope scope,
                   String attributeKey,
                   Operator operator,
                   String expectedValue,
                   Severity severity,
                   String message) {
}
