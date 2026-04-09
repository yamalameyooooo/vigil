package com.vigil.rules;

import org.junit.jupiter.api.Test;
import java.util.Set;
import static org.assertj.core.api.Assertions.assertThat;

class ViolationTest {
    @Test
    void shouldCreateViolationWithAllFields() {
        Violation v = new Violation(
            "VIGIL-SEC-001",
            "Hardcoded Password",
            RuleCategory.SECRETS,
            Severity.CRITICAL,
            "src/main/java/UserService.java",
            42,
            "String dbPass = \"admin123\";",
            Set.of(Framework.SOC2, Framework.GDPR),
            "Hardcoded password detected",
            "Use environment variables or a secrets manager"
        );

        assertThat(v.ruleId()).isEqualTo("VIGIL-SEC-001");
        assertThat(v.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(v.frameworks()).containsExactlyInAnyOrder(Framework.SOC2, Framework.GDPR);
    }

    @Test
    void severityShouldBeOrdered() {
        assertThat(Severity.CRITICAL.ordinal()).isLessThan(Severity.HIGH.ordinal());
        assertThat(Severity.HIGH.ordinal()).isLessThan(Severity.MEDIUM.ordinal());
        assertThat(Severity.MEDIUM.ordinal()).isLessThan(Severity.LOW.ordinal());
    }

    @Test
    void frameworkShouldHaveDisplayName() {
        assertThat(Framework.PCI_DSS.getDisplayName()).isEqualTo("PCI DSS");
        assertThat(Framework.SOC2.getDisplayName()).isEqualTo("SOC 2");
        assertThat(Framework.ISO_27001.getDisplayName()).isEqualTo("ISO 27001");
    }
}
