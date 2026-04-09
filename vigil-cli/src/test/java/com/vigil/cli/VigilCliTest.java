package com.vigil.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class VigilCliTest {

    @Test
    void shouldRunCliSuccessfully(@TempDir Path tempDir) throws Exception {
        // Create a test file with a violation
        Path javaFile = tempDir.resolve("Test.java");
        String javaContent = """
            package com.example;

            public class Test {
                private static final String PASSWORD = "hardcoded123";
            }
            """;
        Files.writeString(javaFile, javaContent);

        // Create output directory
        Path outputDir = tempDir.resolve("output");

        VigilCli cli = new VigilCli();
        CommandLine cmd = new CommandLine(cli);

        int exitCode = cmd.execute(tempDir.toString(), "--output", outputDir.toString());

        assertThat(exitCode).isEqualTo(0);
        assertThat(outputDir.resolve("vigil-report.html")).exists();
    }

    @Test
    void shouldHandleEmptyProjectGracefully(@TempDir Path tempDir) {
        Path outputDir = tempDir.resolve("output");

        VigilCli cli = new VigilCli();
        CommandLine cmd = new CommandLine(cli);

        int exitCode = cmd.execute(tempDir.toString(), "--output", outputDir.toString());

        assertThat(exitCode).isEqualTo(0);
    }
}
