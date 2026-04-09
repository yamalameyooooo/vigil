package com.vigil.scanner;

import com.vigil.rules.RuleRegistry;
import com.vigil.rules.Violation;
import com.vigil.rules.secrets.HardcodedPasswordRule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class ScannerTest {

    @Test
    void shouldScanProjectAndFindViolations(@TempDir Path tempDir) throws Exception {
        // Create a Java file with a violation
        Path javaFile = tempDir.resolve("Test.java");
        String javaContent = """
            package com.example;

            public class Test {
                private static final String PASSWORD = "hardcoded123";
            }
            """;
        Files.writeString(javaFile, javaContent);

        RuleRegistry registry = new RuleRegistry();
        registry.register(new HardcodedPasswordRule());

        Scanner scanner = new Scanner(registry);
        List<Violation> violations = scanner.scan(tempDir);

        assertThat(violations).isNotEmpty();
        assertThat(violations.get(0).ruleId()).isEqualTo("VIGIL-SEC-001");
    }

    @Test
    void shouldReturnEmptyListForProjectWithoutViolations(@TempDir Path tempDir) throws Exception {
        Path javaFile = tempDir.resolve("Clean.java");
        String javaContent = """
            package com.example;

            public class Clean {
                private String name;
            }
            """;
        Files.writeString(javaFile, javaContent);

        RuleRegistry registry = new RuleRegistry();
        registry.register(new HardcodedPasswordRule());

        Scanner scanner = new Scanner(registry);
        List<Violation> violations = scanner.scan(tempDir);

        assertThat(violations).isEmpty();
    }

    @Test
    void shouldHandleEmptyProject(@TempDir Path tempDir) throws Exception {
        RuleRegistry registry = new RuleRegistry();
        Scanner scanner = new Scanner(registry);
        List<Violation> violations = scanner.scan(tempDir);

        assertThat(violations).isEmpty();
    }
}
