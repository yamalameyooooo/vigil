package com.vigil.dependencies;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class MavenPomParserTest {
    private final MavenPomParser parser = new MavenPomParser();

    @Test
    void shouldParseDependenciesFromPom(@TempDir Path tempDir) throws Exception {
        Path pomPath = tempDir.resolve("pom.xml");
        String pomContent = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId>
                <artifactId>test-project</artifactId>
                <version>1.0.0</version>
                <dependencies>
                    <dependency>
                        <groupId>org.springframework</groupId>
                        <artifactId>spring-core</artifactId>
                        <version>5.3.20</version>
                    </dependency>
                    <dependency>
                        <groupId>com.fasterxml.jackson.core</groupId>
                        <artifactId>jackson-databind</artifactId>
                        <version>2.13.0</version>
                    </dependency>
                </dependencies>
            </project>
            """;
        Files.writeString(pomPath, pomContent);

        List<DependencyInfo> dependencies = parser.parse(pomPath);

        assertThat(dependencies).hasSize(2);
        assertThat(dependencies.get(0).groupId()).isEqualTo("org.springframework");
        assertThat(dependencies.get(0).artifactId()).isEqualTo("spring-core");
        assertThat(dependencies.get(0).version()).isEqualTo("5.3.20");
        assertThat(dependencies.get(0).ecosystem()).isEqualTo("Maven");
    }

    @Test
    void shouldReturnEmptyListForPomWithoutDependencies(@TempDir Path tempDir) throws Exception {
        Path pomPath = tempDir.resolve("pom.xml");
        String pomContent = """
            <?xml version="1.0" encoding="UTF-8"?>
            <project xmlns="http://maven.apache.org/POM/4.0.0">
                <modelVersion>4.0.0</modelVersion>
                <groupId>com.example</groupId>
                <artifactId>test-project</artifactId>
                <version>1.0.0</version>
            </project>
            """;
        Files.writeString(pomPath, pomContent);

        List<DependencyInfo> dependencies = parser.parse(pomPath);

        assertThat(dependencies).isEmpty();
    }

    @Test
    void shouldHandleInvalidPomGracefully(@TempDir Path tempDir) throws Exception {
        Path pomPath = tempDir.resolve("pom.xml");
        Files.writeString(pomPath, "invalid xml content");

        List<DependencyInfo> dependencies = parser.parse(pomPath);

        assertThat(dependencies).isEmpty();
    }
}
