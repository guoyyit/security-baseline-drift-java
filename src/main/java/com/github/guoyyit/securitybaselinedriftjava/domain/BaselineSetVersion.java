package com.github.guoyyit.securitybaselinedriftjava.domain;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

/** An immutable, fully materialized version of the baseline set. */
public record BaselineSetVersion(long version, List<BaselineEntry> entries, Instant createdAt) {

    public BaselineSetVersion {
        Objects.requireNonNull(entries, "entries");
        Objects.requireNonNull(createdAt, "createdAt");
        entries = List.copyOf(entries);
    }
}
