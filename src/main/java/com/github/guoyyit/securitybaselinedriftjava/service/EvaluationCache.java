package com.github.guoyyit.securitybaselinedriftjava.service;

import com.github.guoyyit.securitybaselinedriftjava.model.CheckReport;
import com.github.guoyyit.securitybaselinedriftjava.model.ConfigSnapshot;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Bounded LRU cache for incremental checks. The key includes the snapshot
 * content hash plus rule/baseline/exemption versions, so any change to the
 * snapshot or to any configuration generation invalidates naturally (the old
 * key is simply never looked up again and gets evicted). Memory stays bounded
 * by maxEntries regardless of snapshot size or count.
 */
public class EvaluationCache {

    private final int maxEntries;
    private final Map<String, CheckReport> lru;

    public EvaluationCache(int maxEntries) {
        if (maxEntries <= 0) {
            throw new IllegalArgumentException("maxEntries must be positive");
        }
        this.maxEntries = maxEntries;
        this.lru = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<String, CheckReport> eldest) {
                return size() > EvaluationCache.this.maxEntries;
            }
        };
    }

    public static String key(ConfigSnapshot snapshot, long ruleSetVersion,
                             long baselineSetVersion, long exemptionVersion) {
        return snapshot.sourceId() + "|" + snapshot.contentHash()
                + "|r" + ruleSetVersion + "|b" + baselineSetVersion + "|e" + exemptionVersion;
    }

    /**
     * Returns the stored report as-is. Callers must re-stamp volatile metadata
     * (snapshot version, fromCache) because the key intentionally identifies
     * content, not a specific snapshot version.
     */
    public synchronized Optional<CheckReport> get(String key) {
        return Optional.ofNullable(lru.get(key));
    }

    public synchronized void put(String key, CheckReport report) {
        lru.put(key, report);
    }

    public synchronized int size() {
        return lru.size();
    }
}
