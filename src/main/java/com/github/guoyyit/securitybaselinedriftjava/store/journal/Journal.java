package com.github.guoyyit.securitybaselinedriftjava.store.journal;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.github.guoyyit.securitybaselinedriftjava.domain.BaselineSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.Exemption;
import com.github.guoyyit.securitybaselinedriftjava.domain.Finding;
import com.github.guoyyit.securitybaselinedriftjava.domain.RuleSetVersion;

import java.io.Closeable;
import java.io.EOFException;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.util.List;
import java.util.function.Consumer;
import java.util.zip.CRC32;

/**
 * Append-only write-ahead journal with length+CRC framing. A torn tail record
 * (crash mid-write) is detected and truncated on open, so replay only ever sees
 * fully committed records.
 *
 * <p>Frame layout: {@code [length:int][crc32:int][payload:byte[length]]}.
 * Every append ends with an fsync, so a returned LSN means the record is durable.
 */
public class Journal implements Closeable {

    private static final int HEADER_BYTES = Integer.BYTES * 2;

    private final Path file;
    private final ObjectMapper mapper;
    private FileChannel channel;
    private long size;

    /** Type-tagged envelope so records stay polymorphism-free on the wire. */
    private record Envelope(String type, JsonNode data) {
    }

    public Journal(Path file) {
        this.file = file;
        this.mapper = new ObjectMapper().registerModule(new JavaTimeModule())
                .configure(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        open();
    }

    private void open() {
        try {
            Files.createDirectories(file.toAbsolutePath().getParent());
            this.channel = FileChannel.open(file,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.READ,
                    StandardOpenOption.WRITE);
            this.channel.position(this.channel.size());
        } catch (IOException e) {
            throw new UncheckedIOException("failed to open journal " + file, e);
        }
    }

    /** Append one record and fsync; returns the LSN assigned to it. */
    public synchronized long append(JournalRecord record) {
        try {
            byte[] payload = serialize(record);
            ByteBuffer frame = ByteBuffer.allocate(HEADER_BYTES + payload.length);
            frame.putInt(payload.length);
            frame.putInt(crc(payload));
            frame.put(payload);
            frame.flip();
            while (frame.hasRemaining()) {
                channel.write(frame);
            }
            channel.force(true);
            return size++;
        } catch (IOException e) {
            throw new UncheckedIOException("failed to append journal record", e);
        }
    }

    /**
     * Replay all committed records in LSN order. Truncates a torn tail so the
     * next append starts at a clean boundary.
     */
    public synchronized void replay(Consumer<JournalRecord> consumer) {
        try {
            long goodOffset = 0;
            long position = 0;
            long fileSize = channel.size();
            ByteBuffer header = ByteBuffer.allocate(HEADER_BYTES);
            while (position + HEADER_BYTES <= fileSize) {
                header.clear();
                readFully(channel, header, position);
                header.flip();
                int length = header.getInt();
                int expectedCrc = header.getInt();
                if (length < 0 || position + HEADER_BYTES + length > fileSize) {
                    break; // torn or corrupt tail
                }
                ByteBuffer payload = ByteBuffer.allocate(length);
                readFully(channel, payload, position + HEADER_BYTES);
                byte[] bytes = payload.array();
                if (crc(bytes) != expectedCrc) {
                    break; // corrupt record: stop replay here
                }
                consumer.accept(deserialize(bytes));
                position += HEADER_BYTES + length;
                goodOffset = position;
            }
            // truncate torn tail and reset counters
            channel.truncate(goodOffset);
            channel.position(goodOffset);
            this.size = countRecords(goodOffset);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to replay journal " + file, e);
        }
    }

    /** Number of committed records currently in the journal. */
    public synchronized long size() {
        return size;
    }

    /** Replace the whole journal with the given compacted records, atomically. */
    public synchronized void reset(List<JournalRecord> compacted) {
        try {
            Path tmp = file.resolveSibling(file.getFileName() + ".tmp");
            try (FileChannel tmpChannel = FileChannel.open(tmp,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.TRUNCATE_EXISTING)) {
                for (JournalRecord record : compacted) {
                    byte[] payload = serialize(record);
                    ByteBuffer frame = ByteBuffer.allocate(HEADER_BYTES + payload.length);
                    frame.putInt(payload.length);
                    frame.putInt(crc(payload));
                    frame.put(payload);
                    frame.flip();
                    while (frame.hasRemaining()) {
                        tmpChannel.write(frame);
                    }
                }
                tmpChannel.force(true);
            }
            channel.close();
            Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            open();
            this.size = compacted.size();
        } catch (IOException e) {
            throw new UncheckedIOException("failed to reset journal " + file, e);
        }
    }

    @Override
    public synchronized void close() {
        try {
            if (channel != null && channel.isOpen()) {
                channel.close();
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    // ---- serialization helpers ----

    private byte[] serialize(JournalRecord record) throws IOException {
        String type = record.getClass().getSimpleName();
        JsonNode data = mapper.valueToTree(record);
        return mapper.writeValueAsBytes(new Envelope(type, data));
    }

    private JournalRecord deserialize(byte[] bytes) throws IOException {
        Envelope envelope = mapper.readValue(bytes, Envelope.class);
        JsonNode data = envelope.data();
        return switch (envelope.type()) {
            case "SnapshotAccepted" -> new JournalRecord.SnapshotAccepted(
                    mapper.treeToValue(data.get("snapshot"), ConfigSnapshot.class));
            case "RuleSetCommitted" -> new JournalRecord.RuleSetCommitted(
                    mapper.treeToValue(data.get("ruleSet"), RuleSetVersion.class));
            case "BaselineSetCommitted" -> new JournalRecord.BaselineSetCommitted(
                    mapper.treeToValue(data.get("baselineSet"), BaselineSetVersion.class));
            case "ExemptionAdded" -> new JournalRecord.ExemptionAdded(
                    mapper.treeToValue(data.get("exemption"), Exemption.class));
            case "ExemptionRemoved" -> new JournalRecord.ExemptionRemoved(
                    data.get("exemptionId").asText());
            case "FindingAcknowledged" -> new JournalRecord.FindingAcknowledged(
                    data.get("fingerprint").asText(), data.get("operator").asText());
            case "EvaluationCommitted" -> new JournalRecord.EvaluationCommitted(
                    data.get("evalId").asLong(),
                    data.get("sourceId").asText(),
                    data.get("snapshotVersion").asLong(),
                    data.get("ruleSetVersion").asLong(),
                    data.get("baselineVersion").asLong(),
                    data.has("exemptionVersion") ? data.get("exemptionVersion").asLong() : 0,
                    mapper.readerForListOf(Finding.class).readValue(data.get("upserted")));
            default -> throw new IOException("unknown journal record type: " + envelope.type());
        };
    }

    private static int crc(byte[] bytes) {
        CRC32 crc = new CRC32();
        crc.update(bytes);
        return (int) crc.getValue();
    }

    private static void readFully(FileChannel channel, ByteBuffer buffer, long position) throws IOException {
        while (buffer.hasRemaining()) {
            int read = channel.read(buffer, position + buffer.position());
            if (read < 0) {
                throw new EOFException();
            }
        }
    }

    private long countRecords(long upToOffset) throws IOException {
        long count = 0;
        long position = 0;
        ByteBuffer header = ByteBuffer.allocate(HEADER_BYTES);
        while (position + HEADER_BYTES <= upToOffset) {
            header.clear();
            readFully(channel, header, position);
            header.flip();
            int length = header.getInt();
            position += HEADER_BYTES + length;
            count++;
        }
        return count;
    }
}
