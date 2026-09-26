package com.github.guoyyit.securitybaselinedriftjava.model;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Map;
import java.util.TreeMap;

/**
 * A configuration snapshot from one source. Versions are monotonic per source;
 * duplicates / out-of-order arrivals are rejected by the store.
 */
public record ConfigSnapshot(String sourceId,
                             long version,
                             Instant collectedAt,
                             Map<String, String> attributes) {

    /** Deterministic content hash of the attribute map (used by the incremental cache). */
    public String contentHash() {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            for (Map.Entry<String, String> e : new TreeMap<>(attributes).entrySet()) {
                md.update(e.getKey().getBytes(StandardCharsets.UTF_8));
                md.update((byte) 0);
                String v = e.getValue() == null ? "" : e.getValue();
                md.update(v.getBytes(StandardCharsets.UTF_8));
                md.update((byte) 1);
            }
            StringBuilder sb = new StringBuilder();
            for (byte b : md.digest()) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
