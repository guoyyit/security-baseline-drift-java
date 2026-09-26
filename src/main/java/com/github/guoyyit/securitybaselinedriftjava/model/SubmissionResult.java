package com.github.guoyyit.securitybaselinedriftjava.model;

/** Outcome of submitting a snapshot: accepted, or rejected as duplicate/out-of-order/late. */
public record SubmissionResult(boolean accepted, String reason, long effectiveVersion) {
    public static SubmissionResult accepted(long version) {
        return new SubmissionResult(true, "ACCEPTED", version);
    }
    public static SubmissionResult rejected(String reason, long effectiveVersion) {
        return new SubmissionResult(false, reason, effectiveVersion);
    }
}
