package com.github.guoyyit.securitybaselinedriftjava.model;

import java.time.Instant;
import java.util.List;

/** An immutable, versioned baseline set. */
public record BaselineSetVersion(long version, List<Baseline> baselines, Instant createdAt) {
    public BaselineSetVersion {
        baselines = List.copyOf(baselines);
    }
}
