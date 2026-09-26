package com.github.guoyyit.securitybaselinedriftjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Configuration knobs for the drift detection service. */
@ConfigurationProperties(prefix = "drift")
public class DriftProperties {

    /** Directory holding the write-ahead journal. */
    private String journalDir = "data";

    /** Maximum number of cached per-source evaluation results (LRU bound). */
    private int evalCacheMaxSize = 1024;

    /** Whether to re-evaluate all sources after a rule/baseline update. */
    private boolean evaluateOnRuleUpdate = true;

    public String getJournalDir() {
        return journalDir;
    }

    public void setJournalDir(String journalDir) {
        this.journalDir = journalDir;
    }

    public int getEvalCacheMaxSize() {
        return evalCacheMaxSize;
    }

    public void setEvalCacheMaxSize(int evalCacheMaxSize) {
        this.evalCacheMaxSize = evalCacheMaxSize;
    }

    public boolean isEvaluateOnRuleUpdate() {
        return evaluateOnRuleUpdate;
    }

    public void setEvaluateOnRuleUpdate(boolean evaluateOnRuleUpdate) {
        this.evaluateOnRuleUpdate = evaluateOnRuleUpdate;
    }
}
