package com.github.guoyyit.securitybaselinedriftjava.api;

import com.github.guoyyit.securitybaselinedriftjava.model.Baseline;
import com.github.guoyyit.securitybaselinedriftjava.model.CheckReport;
import com.github.guoyyit.securitybaselinedriftjava.model.ConfigSnapshot;
import com.github.guoyyit.securitybaselinedriftjava.model.Exemption;
import com.github.guoyyit.securitybaselinedriftjava.model.Finding;
import com.github.guoyyit.securitybaselinedriftjava.model.FindingStatus;
import com.github.guoyyit.securitybaselinedriftjava.model.Rule;
import com.github.guoyyit.securitybaselinedriftjava.model.SubmissionResult;
import com.github.guoyyit.securitybaselinedriftjava.service.DriftDetectionService;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/** REST API for snapshot submission, versioned config updates and queries. */
@RestController
@RequestMapping("/api/drift")
public class DriftController {

    private final DriftDetectionService service;

    public DriftController(DriftDetectionService service) {
        this.service = service;
    }

    @PostMapping("/snapshots")
    public SubmissionResult submit(@RequestBody ConfigSnapshot snapshot) {
        return service.submitSnapshot(snapshot);
    }

    @PostMapping("/rules")
    public Map<String, Long> publishRules(@RequestBody List<Rule> rules) {
        return Map.of("version", service.publishRules(rules));
    }

    @PostMapping("/baselines")
    public Map<String, Long> publishBaselines(@RequestBody List<Baseline> baselines) {
        return Map.of("version", service.publishBaselines(baselines));
    }

    @PostMapping("/exemptions")
    public Map<String, Long> replaceExemptions(@RequestBody List<Exemption> exemptions) {
        return Map.of("version", service.replaceExemptions(exemptions));
    }

    @PostMapping("/checks/{sourceId}")
    public CheckReport checkSource(@PathVariable String sourceId) {
        return service.checkSource(sourceId);
    }

    @PostMapping("/checks")
    public List<CheckReport> checkAll() {
        return service.checkAll();
    }

    @GetMapping("/findings")
    public List<Finding> findings(@RequestParam Optional<FindingStatus> status) {
        return service.findings(status);
    }

    @PostMapping("/findings/{fingerprint}/acknowledge")
    public Optional<Finding> acknowledge(@PathVariable String fingerprint) {
        return service.acknowledge(fingerprint);
    }
}
