package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.file.Path;
import java.util.List;
import java.util.Map;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** End-to-end REST API smoke test over a real Spring context. */
@SpringBootTest
@AutoConfigureMockMvc
class DriftApiTest {

    @TempDir
    static Path checkpointDir;

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("drift.checkpoint-dir", checkpointDir::toString);
    }

    @Autowired
    MockMvc mvc;

    private final ObjectMapper mapper = new ObjectMapper().registerModule(new JavaTimeModule());

    @Test
    void submitRulesAndSnapshotThenQueryFindings() throws Exception {
        Map<String, Object> rule = Map.of(
                "id", "pwd-policy",
                "scope", Map.of("kind", "GLOBAL", "pattern", "*"),
                "attributeKey", "password.min.length",
                "operator", "EQUALS",
                "expectedValue", "12",
                "severity", "HIGH",
                "message", "password policy mismatch");
        mvc.perform(post("/api/drift/rules")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(List.of(rule))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.version").value(1));

        Map<String, Object> snapshot = Map.of(
                "sourceId", "host-1",
                "version", 1,
                "collectedAt", "2026-09-27T00:00:00Z",
                "attributes", Map.of("password.min.length", "8"));
        mvc.perform(post("/api/drift/snapshots")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(mapper.writeValueAsString(snapshot)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accepted").value(true));

        mvc.perform(get("/api/drift/findings"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].ruleId").value("pwd-policy"))
                .andExpect(jsonPath("$[0].status").value("NEW"));

        mvc.perform(post("/api/drift/checks/host-1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.ruleSetVersion").value(1))
                .andExpect(jsonPath("$.violations[0].ruleId").value("pwd-policy"));
    }
}
