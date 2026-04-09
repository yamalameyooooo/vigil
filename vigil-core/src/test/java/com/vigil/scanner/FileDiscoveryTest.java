package com.vigil.scanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class FileDiscoveryTest {
    @TempDir
    Path tempDir;

    @Test
    void shouldFindJavaFiles() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/java"));
        Files.writeString(tempDir.resolve("src/main/java/App.java"), "class App {}");
        Files.writeString(tempDir.resolve("src/main/java/Util.java"), "class Util {}");
        Files.writeString(tempDir.resolve("readme.md"), "# readme");

        assertThat(new FileDiscovery().discover(tempDir)
            .stream()
            .filter(f -> f.language() == Language.JAVA)
            .toList()
        ).hasSize(2);
    }

    @Test
    void shouldFindJsAndTsFiles() throws IOException {
        Files.createDirectories(tempDir.resolve("src"));
        Files.writeString(tempDir.resolve("src/app.js"), "const x = 1;");
        Files.writeString(tempDir.resolve("src/util.ts"), "const y: number = 2;");
        Files.writeString(tempDir.resolve("src/component.tsx"), "export default () => <div/>;");

        assertThat(new FileDiscovery().discover(tempDir)).hasSize(3);
    }

    @Test
    void shouldSkipNodeModulesAndTarget() throws IOException {
        Files.createDirectories(tempDir.resolve("node_modules/lodash"));
        Files.writeString(tempDir.resolve("node_modules/lodash/index.js"), "module.exports = {};");
        Files.createDirectories(tempDir.resolve("target/classes"));
        Files.writeString(tempDir.resolve("target/classes/App.java"), "class App {}");
        Files.writeString(tempDir.resolve("App.java"), "class App {}");

        assertThat(new FileDiscovery().discover(tempDir)).hasSize(1);
    }

    @Test
    void shouldFindDependencyManifests() throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), "<project/>");
        Files.writeString(tempDir.resolve("package.json"), "{}");

        assertThat(new FileDiscovery().discoverDependencyManifests(tempDir)).hasSize(2);
    }
}
