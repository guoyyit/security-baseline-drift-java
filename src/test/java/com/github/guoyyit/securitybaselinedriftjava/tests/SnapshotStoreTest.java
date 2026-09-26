package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.model.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.model.SubmissionResult;
import com.github.guoyyit.securitybaselinedriftjava.store.SnapshotStore;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class SnapshotStoreTest {

    private ConfigSnapshot snap(String source, long version, String key, String value) {
        return new ConfigSnapshot(source, version, Instant.now(), Map.of(key, value));
    }

    @Test
    void keepsLatestVersionRegardlessOfArrivalOrder() {
        SnapshotStore store = new SnapshotStore();
        assertTrue(store.submit(snap("host-a", 3, "k", "v3")).accepted());
        assertTrue(store.submit(snap("host-a", 5, "k", "v5")).accepted());
        assertTrue(store.submit(snap("host-a", 4, "k", "v4")).accepted() == false);
        assertEquals("v5", store.latest("host-a").orElseThrow().attributes().get("k"));
        assertEquals(5, store.latest("host-a").orElseThrow().version());
    }

    @Test
    void rejectsDuplicatesAndLateArrivals() {
        SnapshotStore store = new SnapshotStore();
        store.submit(snap("host-a", 2, "k", "v2"));

        SubmissionResult dup = store.submit(snap("host-a", 2, "k", "v2-changed"));
        assertFalse(dup.accepted());
        assertEquals("DUPLICATE", dup.reason());

        SubmissionResult late = store.submit(snap("host-a", 1, "k", "v1"));
        assertFalse(late.accepted());
        assertEquals("OUT_OF_ORDER_OR_LATE", late.reason());

        // Final state must equal the newest version's state.
        assertEquals("v2", store.latest("host-a").orElseThrow().attributes().get("k"));
    }

    @Test
    void tracksSourcesIndependently() {
        SnapshotStore store = new SnapshotStore();
        store.submit(snap("a", 5, "k", "va"));
        store.submit(snap("b", 1, "k", "vb"));
        assertEquals(5, store.latest("a").orElseThrow().version());
        assertEquals(1, store.latest("b").orElseThrow().version());
        assertEquals(2, store.allLatest().size());
    }
}
