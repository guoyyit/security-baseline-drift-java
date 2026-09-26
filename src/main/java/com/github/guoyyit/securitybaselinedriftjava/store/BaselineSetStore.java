package com.github.guoyyit.securitybaselinedriftjava.store;

import com.github.guoyyit.securitybaselinedriftjava.domain.BaselineSetVersion;

import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;

/** Versioned baseline set store; same atomic-swap semantics as RuleSetStore. */
public class BaselineSetStore {

    private final AtomicReference<BaselineSetVersion> current = new AtomicReference<>();
    private final ConcurrentHashMap<Long, BaselineSetVersion> history = new ConcurrentHashMap<>();

    public void publish(BaselineSetVersion version) {
        history.put(version.version(), version);
        current.accumulateAndGet(version,
                (existing, incoming) -> existing == null || incoming.version() > existing.version()
                        ? incoming
                        : existing);
    }

    public Optional<BaselineSetVersion> current() {
        return Optional.ofNullable(current.get());
    }

    public Optional<BaselineSetVersion> version(long version) {
        return Optional.ofNullable(history.get(version));
    }

    public void restore(BaselineSetVersion version) {
        publish(version);
    }

    public void clear() {
        current.set(null);
        history.clear();
    }
}
