package com.github.guoyyit.securitybaselinedriftjava.engine;

import com.github.guoyyit.securitybaselinedriftjava.domain.BaselineEntry;
import com.github.guoyyit.securitybaselinedriftjava.domain.BaselineSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.Exemption;
import com.github.guoyyit.securitybaselinedriftjava.domain.Rule;
import com.github.guoyyit.securitybaselinedriftjava.domain.RuleSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.Scope;
import com.github.guoyyit.securitybaselinedriftjava.domain.Violation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Pure evaluation logic: given one snapshot and one complete version of the
 * rule set, baseline set and exemption list, produce the violations.
 *
 * <p>Baseline inheritance: for each config key the effective expectation is the
 * matching entry with the highest scope specificity (SOURCE &gt; GROUP &gt;
 * GLOBAL); ties are broken by explicit priority, then by the later update time.
 * Exemption conflicts resolve the same way (specificity, then latest created).
 * Every decision is written into {@link Violation#explanation()}.
 *
 * <p>Incremental evaluation: results are cached by
 * {@code (sourceId, snapshotVersion, ruleSetVersion, baselineVersion,
 * exemptionVersion, contentHash)}; any version bump invalidates the entry.
 * The cache is an access-order LRU bounded by {@code maxCacheSize}, so memory
 * stays bounded regardless of snapshot size and count.
 */
public class EvaluationEngine {

    /** Cache key for incremental evaluation. */
    private record CacheKey(String sourceId, long snapshotVersion, long ruleSetVersion,
                            long baselineVersion, long exemptionVersion, int contentHash) {
    }

    private final int maxCacheSize;
    private final Map<CacheKey, List<EvaluatedViolation>> cache;

    public EvaluationEngine(int maxCacheSize) {
        this.maxCacheSize = Math.max(1, maxCacheSize);
        this.cache = new LinkedHashMap<>(16, 0.75f, true) {
            @Override
            protected boolean removeEldestEntry(Map.Entry<CacheKey, List<EvaluatedViolation>> eldest) {
                return size() > EvaluationEngine.this.maxCacheSize;
            }
        };
    }

    /** Evaluation outcome plus cache-hit flag. */
    public record Evaluation(List<EvaluatedViolation> violations, boolean fromCache) {
        public Evaluation {
            violations = List.copyOf(violations);
        }
    }

    /** Evaluate, reporting whether the result came from the incremental cache. */
    public synchronized Evaluation evaluateCached(
            ConfigSnapshot snapshot,
            RuleSetVersion ruleSet,
            BaselineSetVersion baselineSet,
            List<Exemption> exemptions,
            long exemptionVersion,
            Instant now) {
        CacheKey key = new CacheKey(snapshot.sourceId(), snapshot.version(),
                ruleSet.version(), baselineSet.version(), exemptionVersion,
                contentHash(snapshot));
        List<EvaluatedViolation> cached = cache.get(key);
        if (cached != null) {
            return new Evaluation(cached, true);
        }
        List<EvaluatedViolation> result = List.copyOf(
                doEvaluate(snapshot, ruleSet, baselineSet, exemptions, now));
        cache.put(key, result);
        return new Evaluation(result, false);
    }

    /** Drop all cached results (called when rule/baseline/exemption versions change). */
    public synchronized void invalidateAll() {
        cache.clear();
    }

    public synchronized int cacheSize() {
        return cache.size();
    }

    // ---- core evaluation ----

    private List<EvaluatedViolation> doEvaluate(
            ConfigSnapshot snapshot,
            RuleSetVersion ruleSet,
            BaselineSetVersion baselineSet,
            List<Exemption> exemptions,
            Instant now) {
        List<EvaluatedViolation> out = new ArrayList<>();
        String sourceId = snapshot.sourceId();
        java.util.Set<String> groups = snapshot.groups();
        java.util.Set<String> ruleCoveredKeys = new java.util.HashSet<>();

        // 1) rule checks
        for (Rule rule : ruleSet.rules()) {
            if (!rule.scope().matches(sourceId, groups)) {
                continue;
            }
            String key = rule.configKey();
            ruleCoveredKeys.add(key);
            String actual = snapshot.configs().get(key);
            String expected = rule.expectedValue();
            String expectationSource = "rule";
            if (expected == null) {
                Optional<ResolvedBaseline> resolved = resolveBaseline(baselineSet, key, sourceId, groups);
                if (resolved.isEmpty()) {
                    continue; // rule references a baseline that does not exist for this source
                }
                expected = resolved.get().entry().expectedValue();
                expectationSource = resolved.get().explanation();
            }
            if (rule.operator() == Rule.Operator.ABSENT) {
                expected = "";
            }
            boolean violated = isViolated(rule.operator(), actual, expected);
            if (violated) {
                String explanation = "rule " + rule.ruleId() + " (scope " + rule.scope()
                        + ", severity " + rule.severity() + "): key '" + key + "' expected "
                        + describeExpectation(rule.operator(), expected)
                        + " but was " + (actual == null ? "<absent>" : "'" + actual + "'")
                        + " [expectation from " + expectationSource + "]";
                out.add(applyExemptions(
                        new Violation(sourceId, rule.ruleId(), key, rule.scope(),
                                rule.severity(), expected, actual, explanation),
                        exemptions, sourceId, groups, now));
            }
        }

        // 2) baseline drift checks for keys not covered by any matching rule
        java.util.Set<String> baselineKeys = new java.util.HashSet<>();
        for (BaselineEntry entry : baselineSet.entries()) {
            if (entry.scope().matches(sourceId, groups)) {
                baselineKeys.add(entry.configKey());
            }
        }
        for (String key : baselineKeys) {
            if (ruleCoveredKeys.contains(key)) {
                continue; // already checked by a rule; avoid double reporting
            }
            Optional<ResolvedBaseline> resolved = resolveBaseline(baselineSet, key, sourceId, groups);
            if (resolved.isEmpty()) {
                continue;
            }
            ResolvedBaseline winner = resolved.get();
            String actual = snapshot.configs().get(key);
            String expected = winner.entry().expectedValue();
            if (!expected.equals(actual)) {
                String explanation = "baseline drift on key '" + key + "': expected '" + expected
                        + "' but was " + (actual == null ? "<absent>" : "'" + actual + "'")
                        + " [inheritance: " + winner.explanation() + "]";
                out.add(applyExemptions(
                        new Violation(sourceId, "baseline-drift", key, winner.entry().scope(),
                                winner.entry().severity(), expected, actual, explanation),
                        exemptions, sourceId, groups, now));
            }
        }
        return out;
    }

    // ---- baseline inheritance with explainability ----

    private record ResolvedBaseline(BaselineEntry entry, String explanation) {
    }

    private Optional<ResolvedBaseline> resolveBaseline(
            BaselineSetVersion baselineSet, String key, String sourceId, java.util.Set<String> groups) {
        List<BaselineEntry> candidates = new ArrayList<>();
        for (BaselineEntry entry : baselineSet.entries()) {
            if (entry.configKey().equals(key) && entry.scope().matches(sourceId, groups)) {
                candidates.add(entry);
            }
        }
        if (candidates.isEmpty()) {
            return Optional.empty();
        }
        candidates.sort(Comparator
                .comparingInt((BaselineEntry e) -> e.scope().specificity())
                .thenComparingLong(BaselineEntry::priority)
                .thenComparingLong(BaselineEntry::updatedAtMillis));
        BaselineEntry winner = candidates.get(candidates.size() - 1);
        StringBuilder explanation = new StringBuilder()
                .append(candidates.size()).append(" candidate(s) for key '").append(key).append("': ");
        for (int i = 0; i < candidates.size(); i++) {
            BaselineEntry c = candidates.get(i);
            explanation.append('[').append(c.scope())
                    .append(" specificity=").append(c.scope().specificity())
                    .append(" priority=").append(c.priority())
                    .append(" updatedAt=").append(c.updatedAtMillis())
                    .append(i == candidates.size() - 1 ? " WINNER" : "")
                    .append(']');
            if (i < candidates.size() - 1) {
                explanation.append(' ');
            }
        }
        return Optional.of(new ResolvedBaseline(winner, explanation.toString()));
    }

    // ---- exemption conflict resolution with explainability ----

    private EvaluatedViolation applyExemptions(
            Violation violation, List<Exemption> exemptions,
            String sourceId, java.util.Set<String> groups, Instant now) {
        List<Exemption> matches = new ArrayList<>();
        for (Exemption e : exemptions) {
            if (!e.isActive(now)) {
                continue;
            }
            if (e.ruleId() != null && !e.ruleId().equals(violation.ruleId())) {
                continue;
            }
            if (e.configKey() != null && !e.configKey().equals(violation.configKey())) {
                continue;
            }
            if (e.scope().matches(sourceId, groups)) {
                matches.add(e);
            }
        }
        if (matches.isEmpty()) {
            return new EvaluatedViolation(violation, null);
        }
        matches.sort(Comparator
                .comparingInt((Exemption e) -> e.scope().specificity())
                .thenComparing(Exemption::createdAt));
        Exemption winner = matches.get(matches.size() - 1);
        StringBuilder explanation = new StringBuilder(violation.explanation())
                .append(" | suppressed by exemption ").append(winner.exemptionId())
                .append(" (scope ").append(winner.scope())
                .append(", reason: ").append(winner.reason())
                .append(", approvedBy: ").append(winner.approvedBy()).append(")");
        if (matches.size() > 1) {
            explanation.append("; conflict resolved among ").append(matches.size())
                    .append(" exemptions by scope specificity then latest createdAt: ");
            for (Exemption m : matches) {
                explanation.append('[').append(m.exemptionId())
                        .append(" specificity=").append(m.scope().specificity())
                        .append(m == winner ? " WINNER" : "").append(']');
            }
        }
        Violation withExplanation = new Violation(
                violation.sourceId(), violation.ruleId(), violation.configKey(), violation.scope(),
                violation.severity(), violation.expectedValue(), violation.actualValue(),
                explanation.toString());
        return new EvaluatedViolation(withExplanation, winner.exemptionId());
    }

    // ---- operator evaluation ----

    private boolean isViolated(Rule.Operator operator, String actual, String expected) {
        return switch (operator) {
            case EQUALS -> !java.util.Objects.equals(actual, expected);
            case NOT_EQUALS -> java.util.Objects.equals(actual, expected);
            case IN -> actual == null || !splitCsv(expected).contains(actual);
            case NOT_IN -> actual != null && splitCsv(expected).contains(actual);
            case REGEX -> actual == null || !actual.matches(expected);
            case GT -> compareNumeric(actual, expected, c -> c <= 0);
            case GTE -> compareNumeric(actual, expected, c -> c < 0);
            case LT -> compareNumeric(actual, expected, c -> c >= 0);
            case LTE -> compareNumeric(actual, expected, c -> c > 0);
            case EXISTS -> actual == null;
            case ABSENT -> actual != null;
        };
    }

    private boolean compareNumeric(String actual, String expected,
                                   java.util.function.IntPredicate violatedWhen) {
        if (actual == null) {
            return true;
        }
        try {
            int cmp = Double.compare(Double.parseDouble(actual), Double.parseDouble(expected));
            return violatedWhen.test(cmp);
        } catch (NumberFormatException e) {
            return true; // unparsable values violate numeric constraints
        }
    }

    private static java.util.Set<String> splitCsv(String csv) {
        java.util.Set<String> out = new java.util.HashSet<>();
        for (String part : csv.split(",")) {
            out.add(part.trim());
        }
        return out;
    }

    private static String describeExpectation(Rule.Operator operator, String expected) {
        return switch (operator) {
            case EXISTS -> "to be present";
            case ABSENT -> "to be absent";
            default -> operator.name().toLowerCase() + " '" + expected + "'";
        };
    }

    private static int contentHash(ConfigSnapshot snapshot) {
        return snapshot.configs().hashCode();
    }
}
