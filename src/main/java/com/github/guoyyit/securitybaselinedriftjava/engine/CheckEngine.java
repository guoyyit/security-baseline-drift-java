package com.github.guoyyit.securitybaselinedriftjava.engine;

import com.github.guoyyit.securitybaselinedriftjava.model.Baseline;
import com.github.guoyyit.securitybaselinedriftjava.model.BaselineSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.model.CheckReport;
import com.github.guoyyit.securitybaselinedriftjava.model.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.model.Rule;
import com.github.guoyyit.securitybaselinedriftjava.model.RuleSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.model.Severity;
import com.github.guoyyit.securitybaselinedriftjava.model.Violation;
import com.github.guoyyit.securitybaselinedriftjava.store.ExemptionStore;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Pattern;

/**
 * Pure evaluation: one snapshot against one complete rule-set version,
 * baseline-set version and exemption-set version. Holds no mutable state,
 * so a run always sees a consistent, unmixed view of its input versions.
 */
@Component
public class CheckEngine {

    /** Synthetic rule id prefix for baseline-drift violations. */
    public static final String DRIFT_RULE_PREFIX = "baseline-drift:";

    private final ScopeResolver scopeResolver;

    public CheckEngine(ScopeResolver scopeResolver) {
        this.scopeResolver = scopeResolver;
    }

    public CheckReport evaluate(ConfigSnapshot snapshot,
                                RuleSetVersion ruleSet,
                                BaselineSetVersion baselineSet,
                                ExemptionStore.ExemptionSet exemptions) {
        List<String> explanations = new ArrayList<>();
        List<Violation> violations = new ArrayList<>();
        Instant now = Instant.now();
        String sourceId = snapshot.sourceId();

        // 1. Rule checks.
        for (Rule rule : scopeResolver.rulesFor(sourceId, ruleSet.rules(), explanations)) {
            String actual = snapshot.attributes().get(rule.attributeKey());
            if (!satisfied(rule, actual)) {
                Optional<com.github.guoyyit.securitybaselinedriftjava.model.Exemption> ex =
                        scopeResolver.exemptionFor(rule.id(), sourceId, exemptions.exemptions(), now, explanations);
                if (ex.isPresent()) {
                    continue; // waived, explanation already recorded
                }
                violations.add(new Violation(rule.id(), rule.attributeKey(),
                        describeExpected(rule), actual, rule.severity(),
                        "rule " + rule.id() + " breached: " + rule.message()));
            }
        }

        // 2. Baseline drift check (with inheritance-resolved baseline).
        Optional<Baseline> baseline = scopeResolver.baselineFor(sourceId, baselineSet.baselines(), explanations);
        if (baseline.isPresent()) {
            for (Map.Entry<String, String> e : baseline.get().attributes().entrySet()) {
                String actual = snapshot.attributes().get(e.getKey());
                if (!e.getValue().equals(actual)) {
                    String driftRuleId = DRIFT_RULE_PREFIX + baseline.get().id();
                    Optional<com.github.guoyyit.securitybaselinedriftjava.model.Exemption> ex =
                            scopeResolver.exemptionFor(driftRuleId, sourceId,
                                    exemptions.exemptions(), now, explanations);
                    if (ex.isPresent()) {
                        continue;
                    }
                    violations.add(new Violation(driftRuleId, e.getKey(), e.getValue(), actual,
                            Severity.MEDIUM,
                            "drift from baseline '" + baseline.get().id() + "' on attribute '" + e.getKey() + "'"));
                }
            }
        }

        return new CheckReport(sourceId, snapshot.version(),
                ruleSet.version(), baselineSet.version(), exemptions.version(),
                violations, explanations, false);
    }

    private boolean satisfied(Rule rule, String actual) {
        return switch (rule.operator()) {
            case EXISTS -> actual != null;
            case NOT_EXISTS -> actual == null;
            case EQUALS -> rule.expectedValue().equals(actual);
            case NOT_EQUALS -> !rule.expectedValue().equals(actual);
            case REGEX_MATCHES -> actual != null && Pattern.matches(rule.expectedValue(), actual);
        };
    }

    private String describeExpected(Rule rule) {
        return switch (rule.operator()) {
            case EXISTS -> "<present>";
            case NOT_EXISTS -> "<absent>";
            default -> rule.expectedValue();
        };
    }
}
