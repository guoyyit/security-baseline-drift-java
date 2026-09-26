package com.github.guoyyit.securitybaselinedriftjava.engine;

import com.github.guoyyit.securitybaselinedriftjava.model.Baseline;
import com.github.guoyyit.securitybaselinedriftjava.model.Exemption;
import com.github.guoyyit.securitybaselinedriftjava.model.Rule;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves which rules / baselines / exemptions apply to a source, with a
 * deterministic, explainable priority: EXACT > REGEX > PREFIX > GLOBAL scope,
 * then explicit priority, then stable id ordering.
 */
@Component
public class ScopeResolver {

    /** All rules whose scope matches the source; every matching rule applies. */
    public List<Rule> rulesFor(String sourceId, List<Rule> rules, List<String> explanations) {
        List<Rule> matched = new ArrayList<>();
        for (Rule r : rules) {
            if (r.scope().matches(sourceId)) {
                matched.add(r);
                explanations.add("rule " + r.id() + " applies to " + sourceId
                        + " via " + r.scope().kind() + " scope '" + r.scope().pattern() + "'");
            } else {
                explanations.add("rule " + r.id() + " skipped for " + sourceId
                        + ": scope " + r.scope().kind() + " '" + r.scope().pattern() + "' does not match");
            }
        }
        return matched;
    }

    /**
     * The effective baseline for a source with configuration inheritance:
     * the most specific matching baseline wins; less specific matching baselines
     * act as ancestors whose attributes are inherited and overridden by more
     * specific ones (GLOBAL is the ultimate parent).
     */
    public Optional<Baseline> baselineFor(String sourceId, List<Baseline> baselines, List<String> explanations) {
        List<Baseline> matched = baselines.stream()
                .filter(b -> b.scope().matches(sourceId))
                .sorted(Comparator.comparingInt((Baseline b) -> b.scope().specificity())
                        .thenComparing(Baseline::id))
                .toList();
        if (matched.isEmpty()) {
            explanations.add("no baseline matches " + sourceId + "; baseline drift check skipped");
            return Optional.empty();
        }
        // Inheritance: merge from least specific (parent) to most specific (child).
        Map<String, String> merged = new LinkedHashMap<>();
        for (Baseline b : matched) {
            merged.putAll(b.attributes());
        }
        Baseline winner = matched.get(matched.size() - 1);
        StringBuilder why = new StringBuilder("baseline '").append(winner.id())
                .append("' wins for ").append(sourceId)
                .append(" (specificity ").append(winner.scope().specificity()).append(")");
        if (matched.size() > 1) {
            why.append("; inherits attributes from ancestors [");
            for (int i = 0; i < matched.size() - 1; i++) {
                if (i > 0) why.append(", ");
                why.append(matched.get(i).id());
            }
            why.append("]");
        }
        explanations.add(why.toString());
        return Optional.of(new Baseline(winner.id(), winner.scope(), Map.copyOf(merged)));
    }

    /**
     * The winning exemption for (ruleId, sourceId), if any active one exists.
     * Conflict resolution: highest priority, then most specific scope, then lowest id.
     */
    public Optional<Exemption> exemptionFor(String ruleId, String sourceId,
                                            List<Exemption> exemptions, Instant now,
                                            List<String> explanations) {
        List<Exemption> candidates = exemptions.stream()
                .filter(e -> e.covers(ruleId, sourceId))
                .toList();
        List<Exemption> active = candidates.stream().filter(e -> e.isActive(now)).toList();
        for (Exemption e : candidates) {
            if (!e.isActive(now)) {
                explanations.add("exemption " + e.id() + " ignored for rule " + ruleId
                        + " on " + sourceId + ": expired at " + e.expiresAt());
            }
        }
        if (active.isEmpty()) {
            return Optional.empty();
        }
        Exemption winner = active.stream()
                .max(Comparator.comparingInt(Exemption::priority)
                        .thenComparingInt(e -> e.scope().specificity())
                        .thenComparing(Exemption::id, Comparator.reverseOrder()))
                .orElseThrow();
        for (Exemption e : active) {
            if (e != winner) {
                explanations.add("exemption conflict on rule " + ruleId + " for " + sourceId
                        + ": '" + e.id() + "' (priority " + e.priority() + ", specificity "
                        + e.scope().specificity() + ") loses to '" + winner.id()
                        + "' (priority " + winner.priority() + ", specificity "
                        + winner.scope().specificity() + ")");
            }
        }
        explanations.add("exemption '" + winner.id() + "' waives rule " + ruleId
                + " on " + sourceId + ": " + winner.reason());
        return Optional.of(winner);
    }
}
