package com.github.guoyyit.securitybaselinedriftjava.domain;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * An immutable, fully materialized version of the rule set. An evaluation always
 * sees exactly one complete RuleSetVersion instance, never a field-level mix.
 */
public record RuleSetVersion(long version, List<Rule> rules, Instant createdAt) {

    public RuleSetVersion {
        Objects.requireNonNull(rules, "rules");
        Objects.requireNonNull(createdAt, "createdAt");
        rules = List.copyOf(rules);
    }
}
