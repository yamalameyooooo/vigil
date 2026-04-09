package com.vigil;

import com.vigil.report.HtmlReportGenerator;
import com.vigil.report.ReportData;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.RuleRegistry;
import com.vigil.rules.Violation;
import com.vigil.rules.accesscontrol.UnauthenticatedEndpointRule;
import com.vigil.rules.encryption.WeakCipherRule;
import com.vigil.rules.encryption.WeakHashAlgorithmRule;
import com.vigil.rules.pii.PiiInLogsRule;
import com.vigil.rules.secrets.HardcodedApiKeyRule;
import com.vigil.rules.secrets.HardcodedPasswordRule;
import com.vigil.scanner.Scanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class VigilIntegrationTest {

    @Test
    void shouldScanProjectWithMultipleViolationTypes(@TempDir Path tempDir) throws Exception {
        // Create Config.java with hardcoded password + API key
        Path configFile = tempDir.resolve("Config.java");
        String configContent = """
            package com.example.config;

            public class Config {
                private static final String DB_PASSWORD = "MySecretPassword123";
                private static final String API_KEY = "sk_live_abcdef123456789";

                public String getPassword() {
                    return DB_PASSWORD;
                }
            }
            """;
        Files.writeString(configFile, configContent);

        // Create CryptoUtil.java with MD5 + DES usage
        Path cryptoFile = tempDir.resolve("CryptoUtil.java");
        String cryptoContent = """
            package com.example.crypto;

            import java.security.MessageDigest;
            import javax.crypto.Cipher;

            public class CryptoUtil {
                public String hashPassword(String password) throws Exception {
                    MessageDigest md = MessageDigest.getInstance("MD5");
                    byte[] hash = md.digest(password.getBytes());
                    return new String(hash);
                }

                public byte[] encrypt(byte[] data, String key) throws Exception {
                    Cipher cipher = Cipher.getInstance("DES");
                    return cipher.doFinal(data);
                }
            }
            """;
        Files.writeString(cryptoFile, cryptoContent);

        // Create UserController.java with @RestController, unauthenticated @GetMapping, and PII in logs
        Path controllerFile = tempDir.resolve("UserController.java");
        String controllerContent = """
            package com.example.controller;

            import org.springframework.web.bind.annotation.GetMapping;
            import org.springframework.web.bind.annotation.RestController;
            import org.slf4j.Logger;
            import org.slf4j.LoggerFactory;

            @RestController
            public class UserController {
                private static final Logger logger = LoggerFactory.getLogger(UserController.class);

                @GetMapping("/api/users")
                public String getUsers() {
                    String userSsn = "123-45-6789";
                    logger.info("User accessed: " + userSsn);
                    return "Users list";
                }
            }
            """;
        Files.writeString(controllerFile, controllerContent);

        // Create Scanner with specific rules registered
        RuleRegistry registry = new RuleRegistry();
        registry.register(new HardcodedPasswordRule());
        registry.register(new HardcodedApiKeyRule());
        registry.register(new WeakHashAlgorithmRule());
        registry.register(new WeakCipherRule());
        registry.register(new UnauthenticatedEndpointRule());
        registry.register(new PiiInLogsRule());

        Scanner scanner = new Scanner(registry);
        List<Violation> violations = scanner.scan(tempDir);

        // Verify at least 6 violations found
        assertThat(violations).hasSizeGreaterThanOrEqualTo(6);

        // Verify different rule types are present
        assertThat(violations).anyMatch(v -> v.ruleId().equals("VIGIL-SEC-001")); // Hardcoded password
        assertThat(violations).anyMatch(v -> v.ruleId().equals("VIGIL-SEC-002")); // Hardcoded API key
        assertThat(violations).anyMatch(v -> v.ruleId().equals("VIGIL-ENC-001")); // Weak hash (MD5)
        assertThat(violations).anyMatch(v -> v.ruleId().equals("VIGIL-ENC-002")); // Weak cipher (DES)
        assertThat(violations).anyMatch(v -> v.ruleId().equals("VIGIL-AC-001")); // Unauthenticated endpoint
        assertThat(violations).anyMatch(v -> v.ruleId().equals("VIGIL-PII-001")); // PII in logs

        // Generate HTML report and verify it exists and contains expected content
        ReportData reportData = new ReportData(
            "integration-test",
            java.time.LocalDateTime.now(),
            3,
            violations
        );

        HtmlReportGenerator htmlGenerator = new HtmlReportGenerator();
        Path reportPath = htmlGenerator.generate(reportData, tempDir.resolve("report"));

        assertThat(reportPath).exists();
        String reportContent = Files.readString(reportPath);

        // Verify report contains expected rule IDs
        assertThat(reportContent).contains("VIGIL-SEC-001");
        assertThat(reportContent).contains("VIGIL-ENC-001");
        assertThat(reportContent).contains("VIGIL-AC-001");

        // Verify PatternFly v6 CSS is loaded
        assertThat(reportContent).contains("@patternfly/patternfly@6");
    }

    @Test
    void shouldProduceCleanReportForCompliantProject(@TempDir Path tempDir) throws Exception {
        // Create a clean Java file with no violations
        Path cleanFile = tempDir.resolve("CleanService.java");
        String cleanContent = """
            package com.example.service;

            import org.springframework.stereotype.Service;

            @Service
            public class CleanService {
                private String serviceName;

                public CleanService(String serviceName) {
                    this.serviceName = serviceName;
                }

                public String getServiceName() {
                    return serviceName;
                }

                public void setServiceName(String serviceName) {
                    this.serviceName = serviceName;
                }
            }
            """;
        Files.writeString(cleanFile, cleanContent);

        // Use Vigil facade to scan
        Vigil vigil = new Vigil();
        ReportData reportData = vigil.scan(tempDir);

        // Verify zero code violations (filter out DEPENDENCIES category since OSV may or may not return results)
        List<Violation> codeViolations = reportData.getViolations().stream()
            .filter(v -> v.category() != RuleCategory.DEPENDENCIES)
            .toList();

        assertThat(codeViolations).isEmpty();
        assertThat(reportData.getFilesScanned()).isGreaterThan(0);
        assertThat(reportData.getProjectName()).isEqualTo(tempDir.getFileName().toString());
    }
}
