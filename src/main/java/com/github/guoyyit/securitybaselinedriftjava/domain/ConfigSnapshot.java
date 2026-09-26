package com.github.guoyyit.securitybaselinedriftjava.domain;

import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * A configuration snapshot submitted by one source.
 *
 * @param sourceId    identifies the source (host / service / device)
 * @param groups      groups the source belongs to, used for scope matching
 * @param version     per-source monotonically increasing snapshot version
 * @param collectedAt time the snapshot was collected at the source
 * @param configs     flattened config key/value map (values rendered as strings)
 */
public record ConfigSnapshot(
        String sourceId,
        Set<String> groups,
        long version,
        Instant collectedAt,
        Map<String, String> configs) {

    public ConfigSnapshot {
        Objects.requireNonNull(sourceId, "sourceId");
        Objects.requireNonNull(collectedAt, "collectedAt");
        Objects.requireNonNull(configs, "configs");
        if (version < 0) {
            throw new IllegalArgumentException("version must be >= 0");
        }
        groups = groups == null ? Set.of() : Set.copyOf(groups);
        configs = Map.copyOf(configs);
    }
}
