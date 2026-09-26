package com.github.guoyyit.securitybaselinedriftjava.store;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.guoyyit.securitybaselinedriftjava.model.BaselineSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.model.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.model.Finding;
import com.github.guoyyit.securitybaselinedriftjava.model.FindingStatus;
import com.github.guoyyit.securitybaselinedriftjava.model.RuleSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.model.Severity;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * File-based crash recovery. Each commit serializes the full committed state to
 * a temp file and atomically renames it over the previous one, so a crash can
 * never leave a partially written checkpoint. The monotonically increasing
 * sequence number identifies the last committed position; on restart the
 * service resumes from exactly that state, neither duplicating nor losing findings.
 */
public class CheckpointStore {

    /** Serializable form of a Finding (the domain class has no default ctor). */
    public record FindingData(String fingerprint, String ruleId, String sourceId, String attributeKey,
                              Severity severity, Instant firstSeen, FindingStatus status,
                              Instant lastSeen, Instant resolvedAt, Instant acknowledgedAt,
                              String detail, long ruleSetVersion, long baselineSetVersion,
                              int occurrences) {
        public static FindingData from(Finding f) {
            return new FindingData(f.getFingerprint(), f.getRuleId(), f.getSourceId(),
                    f.getAttributeKey(), f.getSeverity(), f.getFirstSeen(), f.getStatus(),
                    f.getLastSeen(), f.getResolvedAt(), f.getAcknowledgedAt(), f.getDetail(),
                    f.getRuleSetVersion(), f.getBaselineSetVersion(), f.getOccurrences());
        }

        public Finding toFinding() {
            Finding f = new Finding(ruleId, sourceId, attributeKey, severity,
                    firstSeen, detail, ruleSetVersion, baselineSetVersion);
            f.restoreState(status, lastSeen, resolvedAt, acknowledgedAt, detail,
                    ruleSetVersion, baselineSetVersion, occurrences);
            return f;
        }
    }

    /** The complete committed system state, serialized as one JSON document. */
    public record SystemState(long sequence,
                              List<ConfigSnapshot> snapshots,
                              List<RuleSetVersion> ruleSets,
                              List<BaselineSetVersion> baselineSets,
                              ExemptionStore.ExemptionSet exemptions,
                              List<FindingData> findings) {
    }

    private final Path directory;
    private final Path stateFile;
    private final Path tempFile;
    private final ObjectMapper mapper;

    public CheckpointStore(Path directory) {
        this.directory = directory;
        this.stateFile = directory.resolve("state.json");
        this.tempFile = directory.resolve("state.json.tmp");
        this.mapper = new ObjectMapper()
                .registerModule(new JavaTimeModule())
                .disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    /** Atomically persists the state; returns the committed sequence number. */
    public synchronized long commit(SystemState state) {
        try {
            Files.createDirectories(directory);
            mapper.writeValue(tempFile.toFile(), state);
            Files.move(tempFile, stateFile,
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            return state.sequence();
        } catch (IOException e) {
            throw new UncheckedIOException("failed to commit checkpoint " + state.sequence(), e);
        }
    }

    /** Loads the last committed state, or empty if none exists or the file is unreadable. */
    public synchronized Optional<SystemState> loadLastCommitted() {
        if (!Files.exists(stateFile)) {
            return Optional.empty();
        }
        try {
            return Optional.of(mapper.readValue(stateFile.toFile(), SystemState.class));
        } catch (IOException e) {
            // A torn/corrupted checkpoint must not crash recovery: start clean instead.
            return Optional.empty();
        }
    }
}
