package com.github.guoyyit.securitybaselinedriftjava.store;

import com.github.guoyyit.securitybaselinedriftjava.model.Exemption;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/** Versioned exemption set, swapped atomically as a whole. */
@Component
public class ExemptionStore {

    /** Immutable view of one exemption-set version. */
    public record ExemptionSet(long version, List<Exemption> exemptions, Instant createdAt) {
        public ExemptionSet {
            exemptions = List.copyOf(exemptions);
        }
    }

    private final AtomicReference<ExemptionSet> current =
            new AtomicReference<>(new ExemptionSet(0L, List.of(), Instant.EPOCH));

    /** Replaces the whole set; returns the new version number. */
    public synchronized long replaceAll(List<Exemption> exemptions) {
        long next = current.get().version() + 1;
        current.set(new ExemptionSet(next, exemptions, Instant.now()));
        return next;
    }

    public ExemptionSet current() {
        return current.get();
    }

    public synchronized void restore(ExemptionSet set) {
        if (set.version() > current.get().version()) {
            current.set(set);
        }
    }
}
