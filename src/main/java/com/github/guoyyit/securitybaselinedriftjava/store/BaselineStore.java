package com.github.guoyyit.securitybaselinedriftjava.store;

import com.github.guoyyit.securitybaselinedriftjava.model.Baseline;
import com.github.guoyyit.securitybaselinedriftjava.model.BaselineSetVersion;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentNavigableMap;
import java.util.concurrent.ConcurrentSkipListMap;
import java.util.concurrent.atomic.AtomicReference;

/** Versioned, immutable baseline sets; same consistency guarantees as RuleSetStore. */
@Component
public class BaselineStore {

    private final ConcurrentNavigableMap<Long, BaselineSetVersion> history = new ConcurrentSkipListMap<>();
    private final AtomicReference<BaselineSetVersion> current =
            new AtomicReference<>(new BaselineSetVersion(0L, List.of(), Instant.EPOCH));

    public BaselineStore() {
        history.put(0L, current.get());
    }

    public synchronized long publish(List<Baseline> baselines) {
        long next = current.get().version() + 1;
        BaselineSetVersion v = new BaselineSetVersion(next, baselines, Instant.now());
        history.put(next, v);
        current.set(v);
        return next;
    }

    public BaselineSetVersion current() {
        return current.get();
    }

    public Optional<BaselineSetVersion> version(long version) {
        return Optional.ofNullable(history.get(version));
    }

    public List<Long> versions() {
        return List.copyOf(history.keySet());
    }

    public synchronized void restore(BaselineSetVersion version) {
        history.put(version.version(), version);
        if (version.version() > current.get().version()) {
            current.set(version);
        }
    }
}
