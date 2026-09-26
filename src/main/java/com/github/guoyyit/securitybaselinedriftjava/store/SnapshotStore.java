package com.github.guoyyit.securitybaselinedriftjava.store;

import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Holds the latest accepted snapshot per source. Duplicate, out-of-order or late
 * snapshots (version &lt;= current) are rejected so the stored state always
 * reflects the newest submitted version per source; compliance is therefore
 * always computed from the latest state regardless of arrival order.
 */
public class SnapshotStore {

    public enum AcceptResult { ACCEPTED, DUPLICATE_OR_STALE }

    private final ConcurrentHashMap<String, ConfigSnapshot> latestBySource = new ConcurrentHashMap<>();

    /** True if the snapshot would be rejected as duplicate/out-of-order/late. */
    public boolean isStale(ConfigSnapshot snapshot) {
        ConfigSnapshot current = latestBySource.get(snapshot.sourceId());
        return current != null && snapshot.version() <= current.version();
    }

    /** Accept the snapshot only if its version is newer than the stored one. */
    public AcceptResult accept(ConfigSnapshot snapshot) {
        AcceptResult[] result = new AcceptResult[1];
        latestBySource.compute(snapshot.sourceId(), (sourceId, current) -> {
            if (current == null || snapshot.version() > current.version()) {
                result[0] = AcceptResult.ACCEPTED;
                return snapshot;
            }
            result[0] = AcceptResult.DUPLICATE_OR_STALE;
            return current;
        });
        return result[0];
    }

    public Optional<ConfigSnapshot> latest(String sourceId) {
        return Optional.ofNullable(latestBySource.get(sourceId));
    }

    public Collection<ConfigSnapshot> allLatest() {
        return List.copyOf(latestBySource.values());
    }

    /** Restore hook used by journal replay; trusts record order. */
    public void restore(ConfigSnapshot snapshot) {
        latestBySource.merge(snapshot.sourceId(), snapshot,
                (current, incoming) -> incoming.version() > current.version() ? incoming : current);
    }

    public void clear() {
        latestBySource.clear();
    }
}
