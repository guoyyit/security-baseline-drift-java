package com.github.guoyyit.securitybaselinedriftjava.domain;

/** Lifecycle of a finding. */
public enum FindingStatus {
    /** Violation observed for the first time. */
    NEW,
    /** Violation still present on subsequent evaluations. */
    OPEN,
    /** Violation present but manually acknowledged by an operator. */
    ACKNOWLEDGED,
    /** Violation covered by an active exemption. */
    SUPPRESSED,
    /** Violation no longer present. */
    RESOLVED
}
