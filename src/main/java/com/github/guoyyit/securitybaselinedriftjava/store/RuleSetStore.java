package com.github.guoyyit.securitybaselinedriftjava.store;

import com.github.guoyyit.securitybaselinedriftjava.domain.RuleSetVersion;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Versioned rule set store. The active version is swapped atomically; an
 * evaluation captures the reference once and therefore always sees one complete
 * immutable version, never a field-level mix. Historical versions are retained
 * so past results are reproducible.
 */
public class RuleSetStore {

    private final AtomicReference<RuleSetVersion> current = new AtomicReference<>();
    private final ConcurrentHashMap<Long, RuleSetVersion> history = new ConcurrentHashMap<>();

    /** Publish a new immutable version; version must be greater than current. */
    public void publish(RuleSetVersion version) {
        history.put(version.version(), version);
        current.accumulateAndGet(version,
                (existing, incoming) -> existing == null || incoming.version() > existing.version()
                        ? incoming
                        : existing);
    }

    /** The currently active version, or empty if none published yet. */
    public Optional<RuleSetVersion> current() {
        return Optional.ofNullable(current.get());
    }

    /** Fetch a historical version for reproducible re-evaluation. */
    public Optional<RuleSetVersion> version(long version) {
        return Optional.ofNullable(history.get(version));
    }

    /** Restore hook used by journal replay. */
    public void restore(RuleSetVersion version) {
        publish(version);
    }

    public void clear() {
        current.set(null);
        history.clear();
    }
}
