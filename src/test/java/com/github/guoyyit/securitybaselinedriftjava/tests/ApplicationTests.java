package com.github.guoyyit.securitybaselinedriftjava.tests;

import com.github.guoyyit.securitybaselinedriftjava.service.DriftService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertNotNull;

/**
 * @author Vincent
 * @version 1.0
 */
@SpringBootTest(properties = "drift.journal-dir=${java.io.tmpdir}/drift-app-test-${random.uuid}")
public class ApplicationTests {

    @Autowired
    private DriftService driftService;

    @Test
    public void contentLoad() {
        assertNotNull(driftService);
    }
}
