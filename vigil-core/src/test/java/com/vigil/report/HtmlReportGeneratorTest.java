package com.vigil.report;

import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class HtmlReportGeneratorTest {
    private final HtmlReportGenerator generator = new HtmlReportGenerator();

    @Test
    void shouldGenerateHtmlReportWithViolations(@TempDir Path tempDir) throws Exception {
        Violation violation = new Violation(
            "VIGIL-SEC-001",
            "Hardcoded Password",
            RuleCategory.SECRETS,
            Severity.CRITICAL,
            "/path/to/Test.java",
            10,
            "String password = \"hardcoded\";",
            Set.of(Framework.SOC2, Framework.PCI_DSS),
            "Hardcoded password detected",
            "Use environment variables"
        );

        ReportData data = new ReportData(
            "test-project",
            LocalDateTime.now(),
            5,
            List.of(violation)
        );

        Path reportPath = generator.generate(data, tempDir);

        assertThat(reportPath).exists();
        assertThat(reportPath.getFileName().toString()).isEqualTo("vigil-report.html");

        String content = Files.readString(reportPath);
        assertThat(content).contains("VIGIL — Compliance Scan Report");
        assertThat(content).contains("test-project");
        assertThat(content).contains("VIGIL-SEC-001");
        assertThat(content).contains("Hardcoded Password");
        assertThat(content).contains("SOC 2");
        assertThat(content).contains("PCI DSS");
    }

    @Test
    void shouldGenerateEmptyStateForZeroViolations(@TempDir Path tempDir) throws Exception {
        ReportData data = new ReportData(
            "clean-project",
            LocalDateTime.now(),
            10,
            List.of()
        );

        Path reportPath = generator.generate(data, tempDir);

        assertThat(reportPath).exists();

        String content = Files.readString(reportPath);
        assertThat(content).contains("No Compliance Violations Found");
        assertThat(content).contains("Your codebase passed all compliance checks");
    }
}
