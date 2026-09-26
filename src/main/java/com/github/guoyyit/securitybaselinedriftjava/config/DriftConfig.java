package com.github.guoyyit.securitybaselinedriftjava.config;

import com.github.guoyyit.securitybaselinedriftjava.service.DriftService;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/** Wires the drift service beans. */
@Configuration
@EnableConfigurationProperties(DriftProperties.class)
public class DriftConfig {

    @Bean(destroyMethod = "close")
    public DriftService driftService(DriftProperties properties) {
        DriftService service = new DriftService(properties);
        // recover committed state before the service accepts traffic
        service.recover();
        return service;
    }
}
