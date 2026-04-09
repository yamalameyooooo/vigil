package com.vigil.dependencies;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class NpmPackageParserTest {
    private final NpmPackageParser parser = new NpmPackageParser();

    @Test
    void shouldParseDependenciesFromPackageJson(@TempDir Path tempDir) throws Exception {
        Path packagePath = tempDir.resolve("package.json");
        String packageContent = """
            {
              "name": "test-project",
              "version": "1.0.0",
              "dependencies": {
                "express": "^4.18.0",
                "lodash": "~4.17.21"
              },
              "devDependencies": {
                "jest": ">=29.0.0"
              }
            }
            """;
        Files.writeString(packagePath, packageContent);

        List<DependencyInfo> dependencies = parser.parse(packagePath);

        assertThat(dependencies).hasSize(3);

        DependencyInfo express = dependencies.stream()
            .filter(d -> d.artifactId().equals("express"))
            .findFirst()
            .orElseThrow();
        assertThat(express.version()).isEqualTo("4.18.0");
        assertThat(express.ecosystem()).isEqualTo("npm");

        DependencyInfo lodash = dependencies.stream()
            .filter(d -> d.artifactId().equals("lodash"))
            .findFirst()
            .orElseThrow();
        assertThat(lodash.version()).isEqualTo("4.17.21");

        DependencyInfo jest = dependencies.stream()
            .filter(d -> d.artifactId().equals("jest"))
            .findFirst()
            .orElseThrow();
        assertThat(jest.version()).isEqualTo("29.0.0");
    }

    @Test
    void shouldReturnEmptyListForPackageJsonWithoutDependencies(@TempDir Path tempDir) throws Exception {
        Path packagePath = tempDir.resolve("package.json");
        String packageContent = """
            {
              "name": "test-project",
              "version": "1.0.0"
            }
            """;
        Files.writeString(packagePath, packageContent);

        List<DependencyInfo> dependencies = parser.parse(packagePath);

        assertThat(dependencies).isEmpty();
    }

    @Test
    void shouldHandleInvalidJsonGracefully(@TempDir Path tempDir) throws Exception {
        Path packagePath = tempDir.resolve("package.json");
        Files.writeString(packagePath, "{ invalid json");

        List<DependencyInfo> dependencies = parser.parse(packagePath);

        assertThat(dependencies).isEmpty();
    }
}
