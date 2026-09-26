package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.engine.ScopeResolver;
import com.github.guoyyit.securitybaselinedriftjava.model.Baseline;
import com.github.guoyyit.securitybaselinedriftjava.model.Exemption;
import com.github.guoyyit.securitybaselinedriftjava.model.Scope;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class ScopeResolverTest {

    private final ScopeResolver resolver = new ScopeResolver();

    @Test
    void mostSpecificBaselineWinsAndInheritsFromAncestors() {
        List<Baseline> baselines = List.of(
                new Baseline("global-base", Scope.global(), Map.of("ssh.port", "22", "tls", "1.2")),
                new Baseline("web-prefix", Scope.prefix("web-"), Map.of("tls", "1.3")),
                new Baseline("web-01-exact", Scope.exact("web-01"), Map.of("ssh.port", "2222")));
        List<String> explanations = new ArrayList<>();

        Optional<Baseline> effective = resolver.baselineFor("web-01", baselines, explanations);

        assertTrue(effective.isPresent());
        // exact match wins for ssh.port, prefix overrides tls, global fills the rest
        assertEquals("2222", effective.get().attributes().get("ssh.port"));
        assertEquals("1.3", effective.get().attributes().get("tls"));
        // every decision is explainable
        assertTrue(explanations.stream().anyMatch(s -> s.contains("wins") && s.contains("inherits")));
    }

    @Test
    void exemptionConflictResolvedByPriorityThenSpecificity() {
        List<Exemption> exemptions = List.of(
                new Exemption("low-global", "r1", Scope.global(), "org-wide", 1, null),
                new Exemption("high-global", "r1", Scope.global(), "urgent", 5, null),
                new Exemption("mid-exact", "r1", Scope.exact("host-1"), "this host", 5, null));
        List<String> explanations = new ArrayList<>();

        // same priority -> more specific scope wins
        Optional<Exemption> winner = resolver.exemptionFor("r1", "host-1", exemptions, Instant.now(), explanations);
        assertTrue(winner.isPresent());
        assertEquals("mid-exact", winner.get().id());
        assertTrue(explanations.stream().anyMatch(s -> s.contains("conflict")));

        // without the exact one, higher priority wins
        Optional<Exemption> winner2 = resolver.exemptionFor("r1", "host-2", exemptions, Instant.now(), new ArrayList<>());
        assertEquals("high-global", winner2.orElseThrow().id());
    }

    @Test
    void expiredExemptionDoesNotApply() {
        List<Exemption> exemptions = List.of(
                new Exemption("expired", "r1", Scope.global(), "old",
                        10, Instant.now().minusSeconds(60)));
        List<String> explanations = new ArrayList<>();
        Optional<Exemption> winner = resolver.exemptionFor("r1", "host-1", exemptions, Instant.now(), explanations);
        assertTrue(winner.isEmpty());
        assertTrue(explanations.stream().anyMatch(s -> s.contains("expired")));
    }

    @Test
    void wildcardExemptionCoversAnyRule() {
        List<Exemption> exemptions = List.of(
                new Exemption("all", "*", Scope.prefix("lab-"), "lab machines", 1, null));
        assertTrue(resolver.exemptionFor("anything", "lab-7", exemptions, Instant.now(), new ArrayList<>()).isPresent());
        assertTrue(resolver.exemptionFor("anything", "prod-7", exemptions, Instant.now(), new ArrayList<>()).isEmpty());
    }
}
