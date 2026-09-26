package com.github.guoyyit.securitybaselinedriftjava.store;

import com.github.guoyyit.securitybaselinedriftjava.model.CheckReport;
import com.github.guoyyit.securitybaselinedriftjava.model.Finding;
import com.github.guoyyit.securitybaselinedriftjava.model.FindingStatus;
import com.github.guoyyit.securitybaselinedriftjava.model.Violation;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Deduplicates findings by fingerprint (ruleId|sourceId|attributeKey) and manages
 * their lifecycle: NEW -> PERSISTENT -> RESOLVED, ACKNOWLEDGED as a manual overlay,
 * reopen (back to NEW) when a resolved violation regresses. A resolved risk that
 * stays resolved never alerts again, and one fingerprint never yields two findings.
 */
@Component
public class FindingStore {

    private final Map<String, Finding> byFingerprint = new LinkedHashMap<>();

    /**
     * Applies one check report: creates/updates findings for present violations,
     * resolves active findings of this source whose violations disappeared.
     *
     * @return findings whose state changed (for checkpointing / notifications)
     */
    public synchronized List<Finding> applyReport(CheckReport report) {
        Instant now = Instant.now();
        List<Finding> changed = new ArrayList<>();
        Map<String, Violation> present = new LinkedHashMap<>();
        for (Violation v : report.violations()) {
            present.put(Finding.fingerprint(v.ruleId(), report.sourceId(), v.attributeKey()), v);
        }

        // 1. Create or update findings for violations present in this report.
        for (Map.Entry<String, Violation> e : present.entrySet()) {
            String fp = e.getKey();
            Violation v = e.getValue();
            Finding existing = byFingerprint.get(fp);
            if (existing == null) {
                Finding f = new Finding(v.ruleId(), report.sourceId(), v.attributeKey(),
                        v.severity(), now, v.explanation(),
                        report.ruleSetVersion(), report.baselineSetVersion());
                byFingerprint.put(fp, f);
                changed.add(f);
            } else if (existing.getStatus() == FindingStatus.RESOLVED) {
                existing.reopen(now, v.explanation(), report.ruleSetVersion(), report.baselineSetVersion());
                changed.add(existing);
            } else {
                existing.markStillPresent(now, v.explanation(),
                        report.ruleSetVersion(), report.baselineSetVersion());
                changed.add(existing);
            }
        }

        // 2. Resolve this source's active findings whose violation is gone.
        for (Finding f : byFingerprint.values()) {
            if (!f.getSourceId().equals(report.sourceId())) {
                continue;
            }
            boolean active = f.getStatus() == FindingStatus.NEW
                    || f.getStatus() == FindingStatus.PERSISTENT
                    || f.getStatus() == FindingStatus.ACKNOWLEDGED;
            if (active && !present.containsKey(f.getFingerprint())) {
                f.resolve(now);
                changed.add(f);
            }
        }
        return changed;
    }

    public synchronized Optional<Finding> byFingerprint(String fingerprint) {
        return Optional.ofNullable(byFingerprint.get(fingerprint));
    }

    public synchronized List<Finding> all() {
        return List.copyOf(byFingerprint.values());
    }

    public synchronized List<Finding> byStatus(FindingStatus status) {
        return byFingerprint.values().stream().filter(f -> f.getStatus() == status).toList();
    }

    public synchronized Optional<Finding> acknowledge(String fingerprint) {
        Finding f = byFingerprint.get(fingerprint);
        if (f == null) {
            return Optional.empty();
        }
        f.acknowledge(Instant.now());
        return Optional.of(f);
    }

    public synchronized void restore(Collection<Finding> findings) {
        byFingerprint.clear();
        for (Finding f : findings) {
            byFingerprint.put(f.getFingerprint(), f);
        }
    }
}
