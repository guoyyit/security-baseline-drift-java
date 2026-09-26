package com.github.guoyyit.securitybaselinedriftjava.store;

import com.github.guoyyit.securitybaselinedriftjava.model.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.model.SubmissionResult;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Keeps only the latest snapshot per source. Duplicate, out-of-order or late
 * arrivals are rejected so the final state always reflects the newest version.
 *
 * Ordering rule: a snapshot is newer iff its version is strictly greater;
 * on equal version the earlier-collected one wins and the later arrival is a
 * duplicate. This makes the result independent of arrival order.
 */
@Component
public class SnapshotStore {

    private final ConcurrentHashMap<String, ConfigSnapshot> latestBySource = new ConcurrentHashMap<>();

    public SubmissionResult submit(ConfigSnapshot snapshot) {
        // Atomic per-source merge: only a strictly newer version replaces the stored one.
        SubmissionResult[] result = new SubmissionResult[1];
        latestBySource.merge(snapshot.sourceId(), snapshot, (existing, incoming) -> {
            if (incoming.version() > existing.version()) {
                result[0] = SubmissionResult.accepted(incoming.version());
                return incoming;
            }
            String reason = incoming.version() == existing.version() ? "DUPLICATE" : "OUT_OF_ORDER_OR_LATE";
            result[0] = SubmissionResult.rejected(reason, existing.version());
            return existing;
        });
        if (result[0] == null) {
            result[0] = SubmissionResult.accepted(snapshot.version());
        }
        return result[0];
    }

    public Optional<ConfigSnapshot> latest(String sourceId) {
        return Optional.ofNullable(latestBySource.get(sourceId));
    }

    public Collection<ConfigSnapshot> allLatest() {
        return List.copyOf(latestBySource.values());
    }

    /** Bulk restore during crash recovery; trusts input as already-committed state. */
    public void restore(Collection<ConfigSnapshot> snapshots) {
        latestBySource.clear();
        for (ConfigSnapshot s : snapshots) {
            latestBySource.merge(s.sourceId(), s,
                    (a, b) -> a.version() >= b.version() ? a : b);
        }
    }
}
