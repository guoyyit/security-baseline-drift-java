package com.github.guoyyit.securitybaselinedriftjava.store;

import com.github.guoyyit.securitybaselinedriftjava.domain.Finding;
import com.github.guoyyit.securitybaselinedriftjava.domain.FindingStatus;

import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Finding store keyed by fingerprint. Deduplicates violations and manages the
 * lifecycle NEW -&gt; OPEN -&gt; (ACKNOWLEDGED | SUPPRESSED) -&gt; RESOLVED; a
 * violation reappearing after RESOLVED reopens the same finding instead of
 * creating a duplicate, so a resolved risk never re-alerts as a fresh finding.
 */
public class FindingStore {

    private final ConcurrentHashMap<String, Finding> byFingerprint = new ConcurrentHashMap<>();

    /** Upsert a finding after a transition (used by evaluation commit + replay). */
    public void upsert(Finding finding) {
        byFingerprint.put(finding.fingerprint(), finding);
    }

    public Optional<Finding> byFingerprint(String fingerprint) {
        return Optional.ofNullable(byFingerprint.get(fingerprint));
    }

    public Collection<Finding> all() {
        return List.copyOf(byFingerprint.values());
    }

    public List<Finding> bySource(String sourceId) {
        return byFingerprint.values().stream()
                .filter(f -> f.sourceId().equals(sourceId))
                .toList();
    }

    public List<Finding> byStatus(FindingStatus status) {
        return byFingerprint.values().stream()
                .filter(f -> f.status() == status)
                .toList();
    }

    /**
     * Manual acknowledgement: NEW/OPEN -&gt; ACKNOWLEDGED. RESOLVED and
     * SUPPRESSED findings are returned unchanged.
     */
    public Optional<Finding> acknowledge(String fingerprint, String operator) {
        Finding[] updated = new Finding[1];
        byFingerprint.computeIfPresent(fingerprint, (fp, current) -> {
            if (current.status() == FindingStatus.NEW || current.status() == FindingStatus.OPEN) {
                updated[0] = new Finding(
                        current.fingerprint(), current.sourceId(), current.ruleId(),
                        current.configKey(), current.scope(), current.severity(),
                        current.expectedValue(), current.actualValue(),
                        FindingStatus.ACKNOWLEDGED,
                        current.firstSeenEvalId(), current.lastSeenEvalId(),
                        current.firstSeenAt(), current.lastSeenAt(), current.resolvedAt(),
                        operator, current.suppressedByExemptionId(),
                        current.ruleSetVersion(), current.baselineVersion());
                return updated[0];
            }
            updated[0] = current;
            return current;
        });
        return Optional.ofNullable(updated[0]);
    }

    public void clear() {
        byFingerprint.clear();
    }
}
