package com.github.guoyyit.securitybaselinedriftjava.model;

/** Lifecycle of a finding: NEW -> PERSISTENT -> RESOLVED; ACKNOWLEDGED is a manual overlay. */
public enum FindingStatus {
    NEW,
    PERSISTENT,
    RESOLVED,
    ACKNOWLEDGED
}
