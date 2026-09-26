package com.github.guoyyit.securitybaselinedriftjava.model;

import java.time.Instant;

/**
 * A deduplicated violation finding with lifecycle.
 * Fingerprint = ruleId + sourceId + attributeKey, so repeats update instead of duplicating.
 * Thread confinement: all mutations go through FindingStore's lock.
 */
public class Finding {

    public static String fingerprint(String ruleId, String sourceId, String attributeKey) {
        return ruleId + "|" + sourceId + "|" + attributeKey;
    }

    private final String fingerprint;
    private final String ruleId;
    private final String sourceId;
    private final String attributeKey;
    private final Severity severity;
    private final Instant firstSeen;
    private FindingStatus status;
    private Instant lastSeen;
    private Instant resolvedAt;
    private Instant acknowledgedAt;
    private String detail;
    private long ruleSetVersion;
    private long baselineSetVersion;
    private int occurrences;

    public Finding(String ruleId, String sourceId, String attributeKey, Severity severity,
                   Instant now, String detail, long ruleSetVersion, long baselineSetVersion) {
        this.fingerprint = fingerprint(ruleId, sourceId, attributeKey);
        this.ruleId = ruleId;
        this.sourceId = sourceId;
        this.attributeKey = attributeKey;
        this.severity = severity;
        this.firstSeen = now;
        this.lastSeen = now;
        this.status = FindingStatus.NEW;
        this.detail = detail;
        this.ruleSetVersion = ruleSetVersion;
        this.baselineSetVersion = baselineSetVersion;
        this.occurrences = 1;
    }

    /** Violation still present in a newer check. */
    public void markStillPresent(Instant now, String detail, long ruleSetVersion, long baselineSetVersion) {
        this.occurrences++;
        this.lastSeen = now;
        this.detail = detail;
        this.ruleSetVersion = ruleSetVersion;
        this.baselineSetVersion = baselineSetVersion;
        if (this.status == FindingStatus.NEW) {
            this.status = FindingStatus.PERSISTENT;
        }
        // RESOLVED findings are reopened by the store as NEW, not via this method.
    }

    /** Violation no longer present. */
    public void resolve(Instant now) {
        this.status = FindingStatus.RESOLVED;
        this.resolvedAt = now;
        this.lastSeen = now;
    }

    /** Manual confirmation; only meaningful while active. */
    public void acknowledge(Instant now) {
        if (this.status == FindingStatus.NEW || this.status == FindingStatus.PERSISTENT) {
            this.status = FindingStatus.ACKNOWLEDGED;
            this.acknowledgedAt = now;
        }
    }

    /** A resolved finding whose violation reappears becomes NEW again (reopen). */
    public void reopen(Instant now, String detail, long ruleSetVersion, long baselineSetVersion) {
        this.status = FindingStatus.NEW;
        this.resolvedAt = null;
        this.acknowledgedAt = null;
        this.lastSeen = now;
        this.detail = detail;
        this.ruleSetVersion = ruleSetVersion;
        this.baselineSetVersion = baselineSetVersion;
        this.occurrences++;
    }

    public String getFingerprint() { return fingerprint; }
    public String getRuleId() { return ruleId; }
    public String getSourceId() { return sourceId; }
    public String getAttributeKey() { return attributeKey; }
    public Severity getSeverity() { return severity; }
    public Instant getFirstSeen() { return firstSeen; }
    public FindingStatus getStatus() { return status; }
    public Instant getLastSeen() { return lastSeen; }
    public Instant getResolvedAt() { return resolvedAt; }
    public Instant getAcknowledgedAt() { return acknowledgedAt; }
    public String getDetail() { return detail; }
    public long getRuleSetVersion() { return ruleSetVersion; }
    public long getBaselineSetVersion() { return baselineSetVersion; }
    public int getOccurrences() { return occurrences; }

    /** Restores mutable fields after a reload from checkpoint. */
    public void restoreState(FindingStatus status, Instant lastSeen, Instant resolvedAt,
                             Instant acknowledgedAt, String detail,
                             long ruleSetVersion, long baselineSetVersion, int occurrences) {
        this.status = status;
        this.lastSeen = lastSeen;
        this.resolvedAt = resolvedAt;
        this.acknowledgedAt = acknowledgedAt;
        this.detail = detail;
        this.ruleSetVersion = ruleSetVersion;
        this.baselineSetVersion = baselineSetVersion;
        this.occurrences = occurrences;
    }
}
