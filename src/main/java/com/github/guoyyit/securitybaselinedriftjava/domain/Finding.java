package com.github.guoyyit.securitybaselinedriftjava.domain;

import java.time.Instant;
import java.util.Objects;

/**
 * A tracked violation finding. Identity (fingerprint) is
 * {@code sourceId + ruleId + configKey}; findings are deduplicated by it and
 * transition through {@link FindingStatus} instead of being re-created.
 */
public record Finding(
        String fingerprint,
        String sourceId,
        String ruleId,
        String configKey,
        Scope scope,
        Severity severity,
        String expectedValue,
        String actualValue,
        FindingStatus status,
        long firstSeenEvalId,
        long lastSeenEvalId,
        Instant firstSeenAt,
        Instant lastSeenAt,
        Instant resolvedAt,
        String acknowledgedBy,
        String suppressedByExemptionId,
    long ruleSetVersion,
        long baselineVersion) {

    public Finding {
        Objects.requireNonNull(fingerprint, "fingerprint");
        Objects.requireNonNull(sourceId, "sourceId");
        Objects.requireNonNull(ruleId, "ruleId");
        Objects.requireNonNull(configKey, "configKey");
        Objects.requireNonNull(status, "status");
    }

    public static String fingerprintOf(String sourceId, String ruleId, String configKey) {
        return sourceId + "|" + ruleId + "|" + configKey;
    }

    @com.fasterxml.jackson.annotation.JsonIgnore
    public boolean isActive() {
        return status == FindingStatus.NEW
                || status == FindingStatus.OPEN
                || status == FindingStatus.ACKNOWLEDGED
                || status == FindingStatus.SUPPRESSED;
    }
}
