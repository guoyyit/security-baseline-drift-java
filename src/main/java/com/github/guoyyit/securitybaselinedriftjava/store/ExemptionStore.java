package com.github.guoyyit.securitybaselinedriftjava.store;

import com.github.guoyyit.securitybaselinedriftjava.domain.Exemption;

import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Holds exemptions. The whole list is swapped atomically on every mutation
 * (copy-on-write), so readers always see one consistent exemption set; each
 * swap bumps a version counter used for incremental-cache invalidation.
 */
public class ExemptionStore {

    private final AtomicReference<List<Exemption>> exemptions = new AtomicReference<>(List.of());
    private final AtomicLong version = new AtomicLong(0);

    public synchronized void add(Exemption exemption) {
        exemptions.updateAndGet(list -> {
            java.util.ArrayList<Exemption> copy = new java.util.ArrayList<>(list);
            copy.add(exemption);
            return List.copyOf(copy);
        });
        version.incrementAndGet();
    }

    public synchronized boolean remove(String exemptionId) {
        boolean[] removed = new boolean[1];
        exemptions.updateAndGet(list -> {
            java.util.ArrayList<Exemption> copy = new java.util.ArrayList<>(list);
            removed[0] = copy.removeIf(e -> e.exemptionId().equals(exemptionId));
            return List.copyOf(copy);
        });
        if (removed[0]) {
            version.incrementAndGet();
        }
        return removed[0];
    }

    public Optional<Exemption> byId(String exemptionId) {
        return exemptions.get().stream()
                .filter(e -> e.exemptionId().equals(exemptionId))
                .findFirst();
    }

    /** Immutable snapshot of all exemptions at this moment. */
    public List<Exemption> snapshot() {
        return exemptions.get();
    }

    public long version() {
        return version.get();
    }

    public void restoreAdd(Exemption exemption) {
        add(exemption);
    }

    public void restoreRemove(String exemptionId) {
        remove(exemptionId);
    }

    public void clear() {
        exemptions.set(List.of());
        version.incrementAndGet();
    }
}
