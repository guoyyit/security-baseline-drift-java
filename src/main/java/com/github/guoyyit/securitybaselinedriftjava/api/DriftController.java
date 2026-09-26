package com.github.guoyyit.securitybaselinedriftjava.api;

import com.github.guoyyit.securitybaselinedriftjava.domain.BaselineSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.domain.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.domain.Exemption;
import com.github.guoyyit.securitybaselinedriftjava.domain.Finding;
import com.github.guoyyit.securitybaselinedriftjava.domain.RuleSetVersion;
import com.github.guoyyit.securitybaselinedriftjava.service.DriftService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

/** REST API for snapshot submission, rule/baseline updates and finding queries. */
@RestController
@RequestMapping("/api")
public class DriftController {

    private final DriftService service;

    public DriftController(DriftService service) {
        this.service = service;
    }

    @PostMapping("/snapshots")
    public DriftService.SubmissionResult submitSnapshot(@RequestBody ConfigSnapshot snapshot) {
        return service.submitSnapshot(snapshot);
    }

    @PostMapping("/rulesets")
    public Map<String, Long> publishRuleSet(@RequestBody RuleSetVersion ruleSet) {
        service.publishRuleSet(ruleSet);
        return Map.of("activeVersion", ruleSet.version());
    }

    @PostMapping("/baselines")
    public Map<String, Long> publishBaselineSet(@RequestBody BaselineSetVersion baselineSet) {
        service.publishBaselineSet(baselineSet);
        return Map.of("activeVersion", baselineSet.version());
    }

    @PostMapping("/exemptions")
    public Map<String, String> addExemption(@RequestBody Exemption exemption) {
        service.addExemption(exemption);
        return Map.of("exemptionId", exemption.exemptionId());
    }

    @DeleteMapping("/exemptions/{exemptionId}")
    public ResponseEntity<Map<String, Boolean>> removeExemption(@PathVariable String exemptionId) {
        boolean removed = service.removeExemption(exemptionId);
        return removed
                ? ResponseEntity.ok(Map.of("removed", true))
                : ResponseEntity.notFound().build();
    }

    @PostMapping("/findings/{fingerprint}/ack")
    public ResponseEntity<Finding> acknowledge(@PathVariable String fingerprint,
                                               @RequestParam String operator) {
        return service.acknowledge(fingerprint, operator)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @GetMapping("/findings")
    public List<Finding> findings(@RequestParam(required = false) String sourceId) {
        return sourceId == null ? service.allFindings() : service.findings(sourceId);
    }

    @GetMapping("/findings/{fingerprint}")
    public ResponseEntity<Finding> finding(@PathVariable String fingerprint) {
        return service.finding(fingerprint)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.notFound().build());
    }
}
