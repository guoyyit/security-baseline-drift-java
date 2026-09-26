package com.github.guoyyit.securitybaselinedriftjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/** Tunables for the drift-detection service. */
@Component
@ConfigurationProperties(prefix = "drift")
public class ServiceProperties {

    /** Directory for checkpoint files (crash recovery). */
    private String checkpointDir = System.getProperty("java.io.tmpdir") + "/drift-checkpoints";

    /** Maximum entries of the incremental evaluation cache (bounded memory). */
    private int cacheMaxEntries = 1024;

    public String getCheckpointDir() {
        return checkpointDir;
    }

    public void setCheckpointDir(String checkpointDir) {
        this.checkpointDir = checkpointDir;
    }

    public int getCacheMaxEntries() {
        return cacheMaxEntries;
    }

    public void setCacheMaxEntries(int cacheMaxEntries) {
        this.cacheMaxEntries = cacheMaxEntries;
    }
}
