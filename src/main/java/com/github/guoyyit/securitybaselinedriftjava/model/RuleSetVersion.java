package com.github.guoyyit.securitybaselinedriftjava.model;

import java.time.Instant;
import java.util.List;

/** An immutable, versioned rule set. A check run always sees exactly one complete version. */
public record RuleSetVersion(long version, List<Rule> rules, Instant createdAt) {
    public RuleSetVersion {
        rules = List.copyOf(rules);
    }
}
