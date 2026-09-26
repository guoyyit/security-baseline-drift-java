package com.github.guoyyit.securitybaselinedriftjava.store;

import com.github.guoyyit.securitybaselinedriftjava.model.Rule;
import com.github.guoyyit.securitybaselinedriftjava.model.RuleSetVersion;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Versioned, immutable rule sets. Readers capture the current version reference
 * atomically, so an in-flight check never sees a field-level mix of two versions.
 * All historical versions are retained so past results are reproducible.
 */
@Component
public class RuleSetStore {

    private final ConcurrentNavigableMap<Long, RuleSetVersion> history = new ConcurrentSkipListMap<>();
    private final AtomicReference<RuleSetVersion> current =
            new AtomicReference<>(new RuleSetVersion(0L, List.of(), Instant.EPOCH));

    public RuleSetStore() {
        history.put(0L, current.get());
    }

    /** Publishes a new immutable version; returns its version number. */
    public synchronized long publish(List<Rule> rules) {
        long next = current.get().version() + 1;
        RuleSetVersion v = new RuleSetVersion(next, rules, Instant.now());
        history.put(next, v);
        current.set(v); // single atomic swap: readers see either the old or the new complete version
        return next;
    }

    public RuleSetVersion current() {
        return current.get();
    }

    public Optional<RuleSetVersion> version(long version) {
        return Optional.ofNullable(history.get(version));
    }

    public List<Long> versions() {
        return List.copyOf(history.keySet());
    }

    /** Recovery: install an already-committed version without renumbering. */
    public synchronized void restore(RuleSetVersion version) {
        history.put(version.version(), version);
        if (version.version() > current.get().version()) {
            current.set(version);
        }
    }
}
