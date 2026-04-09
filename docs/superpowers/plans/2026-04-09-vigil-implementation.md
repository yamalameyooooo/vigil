# Vigil Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Vigil, an AST-based compliance static analysis tool that scans Java and JS/TS codebases and produces a PatternFly 6 HTML report.

**Architecture:** Multi-module Maven project. vigil-core contains all scanning logic (AST parsers, rules, report generator). vigil-cli wraps it in a Picocli CLI. vigil-maven-plugin wraps it as a Maven Mojo. vigil-npm packages the CLI JAR for npm distribution. Files are parsed into ASTs, rules visit AST nodes to find violations, and an HTML report is generated.

**Tech Stack:** Java 17, JavaParser 3.x, tree-sitter Java bindings, Picocli 4.x, JMustache, PatternFly 6, Maven Plugin API 3.x, JUnit 5, OSV API (HTTP)

**Spec:** `docs/superpowers/specs/2026-04-09-vigil-design.md`

---

## File Structure

```
vigil/
├── pom.xml                                                  # Parent POM (multi-module)
├── vigil-core/
│   ├── pom.xml                                              # Core module POM
│   └── src/
│       ├── main/java/com/vigil/
│       │   ├── Vigil.java                                   # Public facade
│       │   ├── scanner/
│       │   │   ├── Scanner.java                             # Orchestrator: discovers files, parses, runs rules
│       │   │   ├── FileDiscovery.java                       # Walks dirs, collects source files by type
│       │   │   ├── SourceFile.java                          # Record: path + language enum
│       │   │   ├── Language.java                            # Enum: JAVA, JAVASCRIPT, TYPESCRIPT
│       │   │   └── java/
│       │   │       └── JavaAstScanner.java                  # JavaParser-based: parses + runs Java rules
│       │   ├── rules/
│       │   │   ├── Rule.java                                # Interface: id, name, category, check(CompilationUnit)
│       │   │   ├── RuleRegistry.java                        # Collects all rule instances
│       │   │   ├── Violation.java                           # Immutable data class
│       │   │   ├── Severity.java                            # Enum: CRITICAL, HIGH, MEDIUM, LOW
│       │   │   ├── Framework.java                           # Enum: SOC2, GDPR, HIPAA, PCI_DSS, etc.
│       │   │   ├── RuleCategory.java                        # Enum: SECRETS, PII, DEPENDENCIES, etc.
│       │   │   ├── PiiFieldDetector.java                    # Shared utility: checks if a name suggests PII
│       │   │   ├── secrets/
│       │   │   │   ├── HardcodedPasswordRule.java
│       │   │   │   ├── HardcodedApiKeyRule.java
│       │   │   │   └── HardcodedTokenRule.java
│       │   │   ├── pii/
│       │   │   │   ├── PiiInLogsRule.java
│       │   │   │   ├── PiiInCookiesRule.java
│       │   │   │   └── UnmaskedPiiResponseRule.java
│       │   │   ├── dependencies/
│       │   │   │   └── KnownCveRule.java
│       │   │   ├── storage/
│       │   │   │   ├── UnencryptedFileWriteRule.java
│       │   │   │   └── InsecureCookieRule.java
│       │   │   ├── logging/
│       │   │   │   ├── SensitiveDataInLogsRule.java
│       │   │   │   └── MissingAuditLogRule.java
│       │   │   ├── encryption/
│       │   │   │   ├── WeakHashAlgorithmRule.java
│       │   │   │   ├── WeakCipherRule.java
│       │   │   │   └── WeakTlsRule.java
│       │   │   └── accesscontrol/
│       │   │       ├── UnauthenticatedEndpointRule.java
│       │   │       └── MissingAuthMiddlewareRule.java
│       │   ├── dependencies/
│       │   │   ├── DependencyAnalyzer.java                  # Orchestrates POM/package.json parsing + CVE lookup
│       │   │   ├── DependencyInfo.java                      # Record: groupId/name, artifactId/version
│       │   │   ├── MavenPomParser.java                      # Extracts dependencies from pom.xml
│       │   │   ├── NpmPackageParser.java                    # Extracts dependencies from package.json
│       │   │   └── OsvClient.java                           # HTTP client for OSV API
│       │   └── report/
│       │       ├── ReportGenerator.java                     # Interface
│       │       ├── ReportData.java                          # Aggregated data for template
│       │       ├── HtmlReportGenerator.java                 # Mustache + PF6 implementation
│       │       ├── ConsoleSummaryPrinter.java               # Prints summary to stdout
│       │       └── templates/
│       │           └── report.mustache                      # PF6 HTML template
│       └── test/java/com/vigil/
│           ├── scanner/
│           │   ├── FileDiscoveryTest.java
│           │   ├── ScannerTest.java
│           │   └── java/
│           │       └── JavaAstScannerTest.java
│           ├── rules/
│           │   ├── secrets/
│           │   │   └── HardcodedSecretsRuleTest.java
│           │   ├── pii/
│           │   │   └── PiiRulesTest.java
│           │   ├── encryption/
│           │   │   └── EncryptionRulesTest.java
│           │   ├── logging/
│           │   │   └── LoggingRulesTest.java
│           │   ├── storage/
│           │   │   └── StorageRulesTest.java
│           │   └── accesscontrol/
│           │       └── AccessControlRulesTest.java
│           ├── dependencies/
│           │   ├── MavenPomParserTest.java
│           │   └── NpmPackageParserTest.java
│           ├── report/
│           │   └── HtmlReportGeneratorTest.java
│           └── VigilIntegrationTest.java
├── vigil-cli/
│   ├── pom.xml
│   └── src/
│       ├── main/java/com/vigil/cli/
│       │   └── VigilCli.java
│       └── test/java/com/vigil/cli/
│           └── VigilCliTest.java
├── vigil-maven-plugin/
│   ├── pom.xml
│   └── src/
│       ├── main/java/com/vigil/maven/
│       │   └── VigilMojo.java
│       └── test/java/com/vigil/maven/
│           └── VigilMojoTest.java
└── vigil-npm/
    ├── package.json
    └── bin/
        └── vigil.js
```

---

### Task 1: Project Scaffolding — Parent POM and Module Structure

**Files:**
- Create: `pom.xml` (parent)
- Create: `vigil-core/pom.xml`
- Create: `vigil-cli/pom.xml`
- Create: `vigil-maven-plugin/pom.xml`

- [ ] **Step 1: Create parent POM**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>com.vigil</groupId>
    <artifactId>vigil-parent</artifactId>
    <version>1.0.0-SNAPSHOT</version>
    <packaging>pom</packaging>

    <name>Vigil</name>
    <description>Compliance static analysis tool for Java and JS/TS codebases</description>

    <modules>
        <module>vigil-core</module>
        <module>vigil-cli</module>
        <module>vigil-maven-plugin</module>
    </modules>

    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <javaparser.version>3.26.4</javaparser.version>
        <picocli.version>4.7.6</picocli.version>
        <junit.version>5.11.4</junit.version>
        <jmustache.version>1.16</jmustache.version>
        <jackson.version>2.18.2</jackson.version>
    </properties>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>com.github.javaparser</groupId>
                <artifactId>javaparser-core</artifactId>
                <version>${javaparser.version}</version>
            </dependency>
            <dependency>
                <groupId>info.picocli</groupId>
                <artifactId>picocli</artifactId>
                <version>${picocli.version}</version>
            </dependency>
            <dependency>
                <groupId>com.samskivert</groupId>
                <artifactId>jmustache</artifactId>
                <version>${jmustache.version}</version>
            </dependency>
            <dependency>
                <groupId>com.fasterxml.jackson.core</groupId>
                <artifactId>jackson-databind</artifactId>
                <version>${jackson.version}</version>
            </dependency>
            <dependency>
                <groupId>org.junit.jupiter</groupId>
                <artifactId>junit-jupiter</artifactId>
                <version>${junit.version}</version>
                <scope>test</scope>
            </dependency>
            <dependency>
                <groupId>org.assertj</groupId>
                <artifactId>assertj-core</artifactId>
                <version>3.27.3</version>
                <scope>test</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-surefire-plugin</artifactId>
                <version>3.5.2</version>
            </plugin>
        </plugins>
    </build>
</project>
```

- [ ] **Step 2: Create vigil-core POM**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>com.vigil</groupId>
        <artifactId>vigil-parent</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </parent>

    <artifactId>vigil-core</artifactId>
    <name>Vigil Core</name>
    <description>Core scanning engine for Vigil compliance analysis</description>

    <dependencies>
        <dependency>
            <groupId>com.github.javaparser</groupId>
            <artifactId>javaparser-core</artifactId>
        </dependency>
        <dependency>
            <groupId>com.samskivert</groupId>
            <artifactId>jmustache</artifactId>
        </dependency>
        <dependency>
            <groupId>com.fasterxml.jackson.core</groupId>
            <artifactId>jackson-databind</artifactId>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
        </dependency>
        <dependency>
            <groupId>org.assertj</groupId>
            <artifactId>assertj-core</artifactId>
        </dependency>
    </dependencies>
</project>
```

- [ ] **Step 3: Create vigil-cli POM**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>com.vigil</groupId>
        <artifactId>vigil-parent</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </parent>

    <artifactId>vigil-cli</artifactId>
    <name>Vigil CLI</name>
    <description>Command-line interface for Vigil compliance scanner</description>

    <dependencies>
        <dependency>
            <groupId>com.vigil</groupId>
            <artifactId>vigil-core</artifactId>
            <version>${project.version}</version>
        </dependency>
        <dependency>
            <groupId>info.picocli</groupId>
            <artifactId>picocli</artifactId>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
        </dependency>
        <dependency>
            <groupId>org.assertj</groupId>
            <artifactId>assertj-core</artifactId>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-shade-plugin</artifactId>
                <version>3.6.0</version>
                <executions>
                    <execution>
                        <phase>package</phase>
                        <goals><goal>shade</goal></goals>
                        <configuration>
                            <transformers>
                                <transformer implementation="org.apache.maven.plugins.shade.resource.ManifestResourceTransformer">
                                    <mainClass>com.vigil.cli.VigilCli</mainClass>
                                </transformer>
                            </transformers>
                            <createDependencyReducedPom>false</createDependencyReducedPom>
                        </configuration>
                    </execution>
                </executions>
            </plugin>
        </plugins>
    </build>
</project>
```

- [ ] **Step 4: Create vigil-maven-plugin POM**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <parent>
        <groupId>com.vigil</groupId>
        <artifactId>vigil-parent</artifactId>
        <version>1.0.0-SNAPSHOT</version>
    </parent>

    <artifactId>vigil-maven-plugin</artifactId>
    <packaging>maven-plugin</packaging>
    <name>Vigil Maven Plugin</name>
    <description>Maven plugin for Vigil compliance scanner</description>

    <dependencies>
        <dependency>
            <groupId>com.vigil</groupId>
            <artifactId>vigil-core</artifactId>
            <version>${project.version}</version>
        </dependency>
        <dependency>
            <groupId>org.apache.maven</groupId>
            <artifactId>maven-plugin-api</artifactId>
            <version>3.9.9</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.apache.maven.plugin-tools</groupId>
            <artifactId>maven-plugin-annotations</artifactId>
            <version>3.15.1</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.apache.maven</groupId>
            <artifactId>maven-project</artifactId>
            <version>2.2.1</version>
            <scope>provided</scope>
        </dependency>
        <dependency>
            <groupId>org.junit.jupiter</groupId>
            <artifactId>junit-jupiter</artifactId>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-plugin-plugin</artifactId>
                <version>3.15.1</version>
            </plugin>
        </plugins>
    </build>
</project>
```

- [ ] **Step 5: Create directory structure and verify build compiles**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mkdir -p vigil-core/src/main/java/com/vigil vigil-core/src/test/java/com/vigil vigil-cli/src/main/java/com/vigil/cli vigil-cli/src/test/java/com/vigil/cli vigil-maven-plugin/src/main/java/com/vigil/maven vigil-maven-plugin/src/test/java/com/vigil/maven`

Then run: `mvn validate -q`

Expected: BUILD SUCCESS (validates POM structure)

- [ ] **Step 6: Commit**

```bash
git add pom.xml vigil-core/pom.xml vigil-cli/pom.xml vigil-maven-plugin/pom.xml
git commit -m "feat: scaffold multi-module Maven project structure"
```

---

### Task 2: Core Data Model — Enums, Violation, Rule Interface

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/rules/Severity.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/Framework.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/RuleCategory.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/Violation.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/Rule.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/RuleRegistry.java`
- Create: `vigil-core/src/main/java/com/vigil/scanner/Language.java`
- Create: `vigil-core/src/main/java/com/vigil/scanner/SourceFile.java`
- Test: `vigil-core/src/test/java/com/vigil/rules/ViolationTest.java`

- [ ] **Step 1: Write test for Violation data class**

```java
package com.vigil.rules;

import org.junit.jupiter.api.Test;
import java.util.Set;
import static org.assertj.core.api.Assertions.assertThat;

class ViolationTest {

    @Test
    void shouldCreateViolationWithAllFields() {
        Violation v = new Violation(
            "VIGIL-SEC-001", "Hardcoded Password", RuleCategory.SECRETS,
            Severity.CRITICAL, "src/main/java/UserService.java", 42,
            "String dbPass = \"admin123\";",
            Set.of(Framework.SOC2, Framework.GDPR),
            "Hardcoded password detected in variable assignment",
            "Use environment variables or a secrets manager"
        );

        assertThat(v.ruleId()).isEqualTo("VIGIL-SEC-001");
        assertThat(v.ruleName()).isEqualTo("Hardcoded Password");
        assertThat(v.category()).isEqualTo(RuleCategory.SECRETS);
        assertThat(v.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(v.filePath()).isEqualTo("src/main/java/UserService.java");
        assertThat(v.lineNumber()).isEqualTo(42);
        assertThat(v.codeSnippet()).contains("admin123");
        assertThat(v.frameworks()).containsExactlyInAnyOrder(Framework.SOC2, Framework.GDPR);
        assertThat(v.description()).contains("Hardcoded password");
        assertThat(v.recommendation()).contains("secrets manager");
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=ViolationTest -q`

Expected: COMPILATION FAILURE (classes don't exist yet)

- [ ] **Step 3: Implement enums and Violation record**

`Severity.java`:
```java
package com.vigil.rules;

public enum Severity {
    CRITICAL, HIGH, MEDIUM, LOW
}
```

`Framework.java`:
```java
package com.vigil.rules;

public enum Framework {
    SOC2("SOC 2"), GDPR("GDPR"), HIPAA("HIPAA"), PCI_DSS("PCI DSS"),
    ISO_27001("ISO 27001"), CCPA("CCPA"), LGPD("LGPD"), POPIA("POPIA"),
    PIPEDA("PIPEDA"), PDPA("PDPA");

    private final String displayName;
    Framework(String displayName) { this.displayName = displayName; }
    public String getDisplayName() { return displayName; }
}
```

`RuleCategory.java`:
```java
package com.vigil.rules;

public enum RuleCategory {
    SECRETS("Hardcoded Secrets"), PII("PII Handling"), DEPENDENCIES("Insecure Dependencies"),
    STORAGE("Data Storage"), LOGGING("Logging Compliance"), ENCRYPTION("Encryption Standards"),
    ACCESS_CONTROL("Access Control");

    private final String displayName;
    RuleCategory(String displayName) { this.displayName = displayName; }
    public String getDisplayName() { return displayName; }
}
```

`Violation.java`:
```java
package com.vigil.rules;

import java.util.Set;

public record Violation(
    String ruleId, String ruleName, RuleCategory category, Severity severity,
    String filePath, int lineNumber, String codeSnippet,
    Set<Framework> frameworks, String description, String recommendation
) {}
```

`Rule.java`:
```java
package com.vigil.rules;

import com.github.javaparser.ast.CompilationUnit;
import java.util.List;

public interface Rule {
    String getId();
    String getName();
    RuleCategory getCategory();
    List<Violation> check(CompilationUnit cu, String filePath);
}
```

`RuleRegistry.java`:
```java
package com.vigil.rules;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class RuleRegistry {
    private final List<Rule> rules = new ArrayList<>();
    public void register(Rule rule) { rules.add(rule); }
    public List<Rule> getAllRules() { return Collections.unmodifiableList(rules); }
}
```

`Language.java`:
```java
package com.vigil.scanner;

public enum Language { JAVA, JAVASCRIPT, TYPESCRIPT }
```

`SourceFile.java`:
```java
package com.vigil.scanner;

import java.nio.file.Path;

public record SourceFile(Path path, Language language) {}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=ViolationTest -q`

Expected: Tests run: 3, Failures: 0

- [ ] **Step 5: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add core data model - enums, Violation record, Rule interface"
```

---

### Task 3: File Discovery

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/scanner/FileDiscovery.java`
- Test: `vigil-core/src/test/java/com/vigil/scanner/FileDiscoveryTest.java`

- [ ] **Step 1: Write failing test**

```java
package com.vigil.scanner;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class FileDiscoveryTest {

    @TempDir Path tempDir;

    @Test
    void shouldFindJavaFiles() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/java"));
        Files.writeString(tempDir.resolve("src/main/java/App.java"), "class App {}");
        Files.writeString(tempDir.resolve("src/main/java/Util.java"), "class Util {}");
        Files.writeString(tempDir.resolve("readme.md"), "# readme");

        List<SourceFile> files = new FileDiscovery().discover(tempDir);
        List<SourceFile> javaFiles = files.stream().filter(f -> f.language() == Language.JAVA).toList();
        assertThat(javaFiles).hasSize(2);
    }

    @Test
    void shouldFindJsAndTsFiles() throws IOException {
        Files.createDirectories(tempDir.resolve("src"));
        Files.writeString(tempDir.resolve("src/app.js"), "const x = 1;");
        Files.writeString(tempDir.resolve("src/util.ts"), "const y: number = 2;");
        Files.writeString(tempDir.resolve("src/component.tsx"), "export default () => <div/>;");

        List<SourceFile> files = new FileDiscovery().discover(tempDir);
        assertThat(files).hasSize(3);
    }

    @Test
    void shouldSkipNodeModulesAndTarget() throws IOException {
        Files.createDirectories(tempDir.resolve("node_modules/lodash"));
        Files.writeString(tempDir.resolve("node_modules/lodash/index.js"), "module.exports = {};");
        Files.createDirectories(tempDir.resolve("target/classes"));
        Files.writeString(tempDir.resolve("target/classes/App.java"), "class App {}");
        Files.writeString(tempDir.resolve("App.java"), "class App {}");

        List<SourceFile> files = new FileDiscovery().discover(tempDir);
        assertThat(files).hasSize(1);
    }

    @Test
    void shouldFindDependencyManifests() throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), "<project/>");
        Files.writeString(tempDir.resolve("package.json"), "{}");

        List<Path> manifests = new FileDiscovery().discoverDependencyManifests(tempDir);
        assertThat(manifests).hasSize(2);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=FileDiscoveryTest -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement FileDiscovery**

```java
package com.vigil.scanner;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class FileDiscovery {

    private static final Set<String> SKIP_DIRS = Set.of(
        "node_modules", "target", "build", "dist", ".git", ".idea", ".vscode",
        "vendor", "bin", ".gradle", "out"
    );

    public List<SourceFile> discover(Path root) throws IOException {
        List<SourceFile> sourceFiles = new ArrayList<>();
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (SKIP_DIRS.contains(dir.getFileName().toString())) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                String fileName = file.getFileName().toString();
                if (fileName.endsWith(".java")) {
                    sourceFiles.add(new SourceFile(file, Language.JAVA));
                } else if (fileName.endsWith(".js")) {
                    sourceFiles.add(new SourceFile(file, Language.JAVASCRIPT));
                } else if (fileName.endsWith(".ts") || fileName.endsWith(".tsx")) {
                    sourceFiles.add(new SourceFile(file, Language.TYPESCRIPT));
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return sourceFiles;
    }

    public List<Path> discoverDependencyManifests(Path root) throws IOException {
        List<Path> manifests = new ArrayList<>();
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                if (SKIP_DIRS.contains(dir.getFileName().toString())) {
                    return FileVisitResult.SKIP_SUBTREE;
                }
                return FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                String fileName = file.getFileName().toString();
                if (fileName.equals("pom.xml") || fileName.equals("package.json")) {
                    manifests.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return manifests;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=FileDiscoveryTest -q`

Expected: Tests run: 4, Failures: 0

- [ ] **Step 5: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add FileDiscovery for walking project directories"
```

---

### Task 4: Java AST Scanner

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/scanner/java/JavaAstScanner.java`
- Test: `vigil-core/src/test/java/com/vigil/scanner/java/JavaAstScannerTest.java`

- [ ] **Step 1: Write failing test**

```java
package com.vigil.scanner.java;

import com.vigil.rules.*;
import com.github.javaparser.ast.CompilationUnit;
import org.junit.jupiter.api.Test;
import java.util.List;
import java.util.Set;
import static org.assertj.core.api.Assertions.assertThat;

class JavaAstScannerTest {

    @Test
    void shouldParseJavaSourceAndRunRules() {
        String source = "public class UserService { private String password = \"admin123\"; }";

        Rule testRule = new Rule() {
            @Override public String getId() { return "TEST-001"; }
            @Override public String getName() { return "Test Rule"; }
            @Override public RuleCategory getCategory() { return RuleCategory.SECRETS; }
            @Override
            public List<Violation> check(CompilationUnit cu, String filePath) {
                List<Violation> violations = new java.util.ArrayList<>();
                cu.findAll(com.github.javaparser.ast.body.VariableDeclarator.class).forEach(v -> {
                    if (v.getNameAsString().equalsIgnoreCase("password")
                            && v.getInitializer().isPresent()
                            && v.getInitializer().get().isStringLiteralExpr()) {
                        violations.add(new Violation(getId(), getName(), getCategory(), Severity.CRITICAL,
                            filePath, v.getBegin().map(p -> p.line).orElse(0), v.toString(),
                            Set.of(Framework.SOC2), "Hardcoded password", "Use env vars"));
                    }
                });
                return violations;
            }
        };

        RuleRegistry registry = new RuleRegistry();
        registry.register(testRule);

        JavaAstScanner scanner = new JavaAstScanner(registry);
        List<Violation> violations = scanner.scan(source, "UserService.java");

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).ruleId()).isEqualTo("TEST-001");
    }

    @Test
    void shouldReturnEmptyForUnparseableSource() {
        JavaAstScanner scanner = new JavaAstScanner(new RuleRegistry());
        List<Violation> violations = scanner.scan("not valid java {{{{", "Bad.java");
        assertThat(violations).isEmpty();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=JavaAstScannerTest -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement JavaAstScanner**

```java
package com.vigil.scanner.java;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.Rule;
import com.vigil.rules.RuleRegistry;
import com.vigil.rules.Violation;

import java.util.ArrayList;
import java.util.List;

public class JavaAstScanner {

    private final RuleRegistry registry;

    public JavaAstScanner(RuleRegistry registry) {
        this.registry = registry;
    }

    public List<Violation> scan(String source, String filePath) {
        JavaParser parser = new JavaParser();
        ParseResult<CompilationUnit> result = parser.parse(source);

        if (!result.isSuccessful() || result.getResult().isEmpty()) {
            return List.of();
        }

        CompilationUnit cu = result.getResult().get();
        List<Violation> violations = new ArrayList<>();
        for (Rule rule : registry.getAllRules()) {
            violations.addAll(rule.check(cu, filePath));
        }
        return violations;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=JavaAstScannerTest -q`

Expected: Tests run: 2, Failures: 0

- [ ] **Step 5: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add JavaAstScanner using JavaParser"
```

---

### Task 5: Hardcoded Secrets Rules

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/rules/secrets/HardcodedPasswordRule.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/secrets/HardcodedApiKeyRule.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/secrets/HardcodedTokenRule.java`
- Test: `vigil-core/src/test/java/com/vigil/rules/secrets/HardcodedSecretsRuleTest.java`

- [ ] **Step 1: Write failing tests**

```java
package com.vigil.rules.secrets;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.*;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class HardcodedSecretsRuleTest {

    private CompilationUnit parse(String source) {
        return new JavaParser().parse(source).getResult().orElseThrow();
    }

    @Test
    void shouldDetectHardcodedPasswordInField() {
        CompilationUnit cu = parse("public class Config { private String password = \"secret123\"; }");
        List<Violation> violations = new HardcodedPasswordRule().check(cu, "Config.java");
        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).ruleId()).isEqualTo("VIGIL-SEC-001");
        assertThat(violations.get(0).severity()).isEqualTo(Severity.CRITICAL);
        assertThat(violations.get(0).frameworks()).contains(Framework.SOC2, Framework.PCI_DSS);
    }

    @Test
    void shouldDetectHardcodedPasswordInLocalVar() {
        CompilationUnit cu = parse("public class Db { void connect() { String dbPassword = \"admin\"; } }");
        List<Violation> violations = new HardcodedPasswordRule().check(cu, "Db.java");
        assertThat(violations).hasSize(1);
    }

    @Test
    void shouldNotFlagPasswordReadFromEnvVar() {
        CompilationUnit cu = parse("public class Config { private String password = System.getenv(\"DB_PASSWORD\"); }");
        List<Violation> violations = new HardcodedPasswordRule().check(cu, "Config.java");
        assertThat(violations).isEmpty();
    }

    @Test
    void shouldDetectHardcodedApiKey() {
        CompilationUnit cu = parse("public class Client { private String apiKey = \"sk-1234567890abcdef\"; }");
        List<Violation> violations = new HardcodedApiKeyRule().check(cu, "Client.java");
        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).ruleId()).isEqualTo("VIGIL-SEC-002");
    }

    @Test
    void shouldNotFlagApiKeyWithoutValue() {
        CompilationUnit cu = parse("public class Client { private String apiKey; }");
        List<Violation> violations = new HardcodedApiKeyRule().check(cu, "Client.java");
        assertThat(violations).isEmpty();
    }

    @Test
    void shouldDetectHardcodedToken() {
        CompilationUnit cu = parse("public class Auth { private String authToken = \"eyJhbG\"; private String secretKey = \"my-key-123\"; }");
        List<Violation> violations = new HardcodedTokenRule().check(cu, "Auth.java");
        assertThat(violations).hasSize(2);
        assertThat(violations.get(0).ruleId()).isEqualTo("VIGIL-SEC-003");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=HardcodedSecretsRuleTest -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement HardcodedPasswordRule**

```java
package com.vigil.rules.secrets;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.vigil.rules.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class HardcodedPasswordRule implements Rule {

    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
        ".*(password|passwd|pwd|passphrase|credential).*", Pattern.CASE_INSENSITIVE);

    @Override public String getId() { return "VIGIL-SEC-001"; }
    @Override public String getName() { return "Hardcoded Password"; }
    @Override public RuleCategory getCategory() { return RuleCategory.SECRETS; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(VariableDeclarator.class).forEach(v -> {
            if (PASSWORD_PATTERN.matcher(v.getNameAsString()).matches()
                    && v.getInitializer().isPresent()
                    && v.getInitializer().get().isStringLiteralExpr()) {
                violations.add(new Violation(getId(), getName(), getCategory(), Severity.CRITICAL, filePath,
                    v.getBegin().map(p -> p.line).orElse(0), v.toString(),
                    Set.of(Framework.SOC2, Framework.GDPR, Framework.HIPAA, Framework.PCI_DSS, Framework.ISO_27001),
                    "Hardcoded password found in variable '" + v.getNameAsString() + "'",
                    "Use environment variables, a secrets manager (e.g., HashiCorp Vault, AWS Secrets Manager), or a configuration service"));
            }
        });
        return violations;
    }
}
```

- [ ] **Step 4: Implement HardcodedApiKeyRule**

```java
package com.vigil.rules.secrets;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.vigil.rules.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class HardcodedApiKeyRule implements Rule {

    private static final Pattern API_KEY_PATTERN = Pattern.compile(
        ".*(api[_\\-]?key|apikey|api[_\\-]?secret).*", Pattern.CASE_INSENSITIVE);

    @Override public String getId() { return "VIGIL-SEC-002"; }
    @Override public String getName() { return "Hardcoded API Key"; }
    @Override public RuleCategory getCategory() { return RuleCategory.SECRETS; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(VariableDeclarator.class).forEach(v -> {
            if (API_KEY_PATTERN.matcher(v.getNameAsString()).matches()
                    && v.getInitializer().isPresent()
                    && v.getInitializer().get().isStringLiteralExpr()) {
                violations.add(new Violation(getId(), getName(), getCategory(), Severity.CRITICAL, filePath,
                    v.getBegin().map(p -> p.line).orElse(0), v.toString(),
                    Set.of(Framework.SOC2, Framework.GDPR, Framework.HIPAA, Framework.PCI_DSS, Framework.ISO_27001),
                    "Hardcoded API key found in variable '" + v.getNameAsString() + "'",
                    "Store API keys in environment variables or a secrets manager. Never commit secrets to source control."));
            }
        });
        return violations;
    }
}
```

- [ ] **Step 5: Implement HardcodedTokenRule**

```java
package com.vigil.rules.secrets;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.vigil.rules.*;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class HardcodedTokenRule implements Rule {

    private static final Pattern TOKEN_PATTERN = Pattern.compile(
        ".*(token|secret[_\\-]?key|auth[_\\-]?key|private[_\\-]?key|access[_\\-]?key|signing[_\\-]?key).*",
        Pattern.CASE_INSENSITIVE);

    @Override public String getId() { return "VIGIL-SEC-003"; }
    @Override public String getName() { return "Hardcoded Token/Secret Key"; }
    @Override public RuleCategory getCategory() { return RuleCategory.SECRETS; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(VariableDeclarator.class).forEach(v -> {
            if (TOKEN_PATTERN.matcher(v.getNameAsString()).matches()
                    && v.getInitializer().isPresent()
                    && v.getInitializer().get().isStringLiteralExpr()) {
                violations.add(new Violation(getId(), getName(), getCategory(), Severity.CRITICAL, filePath,
                    v.getBegin().map(p -> p.line).orElse(0), v.toString(),
                    Set.of(Framework.SOC2, Framework.GDPR, Framework.HIPAA, Framework.PCI_DSS, Framework.ISO_27001),
                    "Hardcoded token/secret key found in variable '" + v.getNameAsString() + "'",
                    "Use environment variables or a secrets manager. Rotate this token immediately if it was ever committed."));
            }
        });
        return violations;
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=HardcodedSecretsRuleTest -q`

Expected: Tests run: 6, Failures: 0

- [ ] **Step 7: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add hardcoded secrets detection rules (password, API key, token)"
```

---

### Task 6: Encryption Rules

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/rules/encryption/WeakHashAlgorithmRule.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/encryption/WeakCipherRule.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/encryption/WeakTlsRule.java`
- Test: `vigil-core/src/test/java/com/vigil/rules/encryption/EncryptionRulesTest.java`

- [ ] **Step 1: Write failing tests**

```java
package com.vigil.rules.encryption;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.*;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class EncryptionRulesTest {
    private CompilationUnit parse(String source) {
        return new JavaParser().parse(source).getResult().orElseThrow();
    }

    @Test
    void shouldDetectMD5Usage() {
        CompilationUnit cu = parse("import java.security.MessageDigest; public class H { void h() throws Exception { MessageDigest md = MessageDigest.getInstance(\"MD5\"); } }");
        List<Violation> v = new WeakHashAlgorithmRule().check(cu, "H.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).ruleId()).isEqualTo("VIGIL-ENC-001");
        assertThat(v.get(0).severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void shouldDetectSHA1Usage() {
        CompilationUnit cu = parse("import java.security.MessageDigest; public class H { void h() throws Exception { MessageDigest.getInstance(\"SHA-1\"); } }");
        assertThat(new WeakHashAlgorithmRule().check(cu, "H.java")).hasSize(1);
    }

    @Test
    void shouldAllowSHA256() {
        CompilationUnit cu = parse("import java.security.MessageDigest; public class H { void h() throws Exception { MessageDigest.getInstance(\"SHA-256\"); } }");
        assertThat(new WeakHashAlgorithmRule().check(cu, "H.java")).isEmpty();
    }

    @Test
    void shouldDetectDESCipher() {
        CompilationUnit cu = parse("import javax.crypto.Cipher; public class E { void e() throws Exception { Cipher.getInstance(\"DES/ECB/PKCS5Padding\"); } }");
        List<Violation> v = new WeakCipherRule().check(cu, "E.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).ruleId()).isEqualTo("VIGIL-ENC-002");
        assertThat(v.get(0).severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void shouldDetectECBMode() {
        CompilationUnit cu = parse("import javax.crypto.Cipher; public class E { void e() throws Exception { Cipher.getInstance(\"AES/ECB/PKCS5Padding\"); } }");
        List<Violation> v = new WeakCipherRule().check(cu, "E.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).description()).contains("ECB");
    }

    @Test
    void shouldAllowAESCBC() {
        CompilationUnit cu = parse("import javax.crypto.Cipher; public class E { void e() throws Exception { Cipher.getInstance(\"AES/CBC/PKCS5Padding\"); } }");
        assertThat(new WeakCipherRule().check(cu, "E.java")).isEmpty();
    }

    @Test
    void shouldDetectTLS10() {
        CompilationUnit cu = parse("import javax.net.ssl.SSLContext; public class S { void s() throws Exception { SSLContext.getInstance(\"TLSv1\"); } }");
        List<Violation> v = new WeakTlsRule().check(cu, "S.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).ruleId()).isEqualTo("VIGIL-ENC-003");
        assertThat(v.get(0).severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void shouldAllowTLS13() {
        CompilationUnit cu = parse("import javax.net.ssl.SSLContext; public class S { void s() throws Exception { SSLContext.getInstance(\"TLSv1.3\"); } }");
        assertThat(new WeakTlsRule().check(cu, "S.java")).isEmpty();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=EncryptionRulesTest -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement WeakHashAlgorithmRule**

```java
package com.vigil.rules.encryption;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.vigil.rules.*;
import java.util.*;

public class WeakHashAlgorithmRule implements Rule {
    private static final Set<String> WEAK_HASHES = Set.of("MD5", "MD2", "MD4", "SHA1", "SHA-1");

    @Override public String getId() { return "VIGIL-ENC-001"; }
    @Override public String getName() { return "Weak Hash Algorithm"; }
    @Override public RuleCategory getCategory() { return RuleCategory.ENCRYPTION; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(MethodCallExpr.class).forEach(call -> {
            if (call.getNameAsString().equals("getInstance")
                    && call.getScope().isPresent()
                    && call.getScope().get().toString().equals("MessageDigest")
                    && !call.getArguments().isEmpty()
                    && call.getArgument(0).isStringLiteralExpr()) {
                String alg = call.getArgument(0).asStringLiteralExpr().getValue();
                if (WEAK_HASHES.contains(alg.toUpperCase())) {
                    violations.add(new Violation(getId(), getName(), getCategory(), Severity.HIGH, filePath,
                        call.getBegin().map(p -> p.line).orElse(0), call.toString(),
                        Set.of(Framework.PCI_DSS, Framework.HIPAA, Framework.SOC2, Framework.ISO_27001),
                        "Weak hash algorithm '" + alg + "' detected. This is cryptographically broken.",
                        "Replace with SHA-256, SHA-384, SHA-512, or SHA-3. For password hashing, use bcrypt, scrypt, or Argon2."));
                }
            }
        });
        return violations;
    }
}
```

- [ ] **Step 4: Implement WeakCipherRule**

```java
package com.vigil.rules.encryption;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.vigil.rules.*;
import java.util.*;

public class WeakCipherRule implements Rule {
    private static final Set<String> WEAK_CIPHERS = Set.of("DES", "DESEDE", "RC4", "RC2", "BLOWFISH");

    @Override public String getId() { return "VIGIL-ENC-002"; }
    @Override public String getName() { return "Weak Cipher Algorithm"; }
    @Override public RuleCategory getCategory() { return RuleCategory.ENCRYPTION; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(MethodCallExpr.class).forEach(call -> {
            if (call.getNameAsString().equals("getInstance")
                    && call.getScope().isPresent()
                    && call.getScope().get().toString().equals("Cipher")
                    && !call.getArguments().isEmpty()
                    && call.getArgument(0).isStringLiteralExpr()) {
                String transformation = call.getArgument(0).asStringLiteralExpr().getValue();
                String algorithm = transformation.split("/")[0].toUpperCase();
                if (WEAK_CIPHERS.contains(algorithm)) {
                    violations.add(new Violation(getId(), getName(), getCategory(), Severity.CRITICAL, filePath,
                        call.getBegin().map(p -> p.line).orElse(0), call.toString(),
                        Set.of(Framework.PCI_DSS, Framework.HIPAA, Framework.SOC2, Framework.ISO_27001),
                        "Weak cipher algorithm '" + algorithm + "' detected.",
                        "Use AES-256 with GCM mode (AES/GCM/NoPadding) for symmetric encryption."));
                } else if (transformation.toUpperCase().contains("/ECB/")) {
                    violations.add(new Violation(getId(), getName(), getCategory(), Severity.CRITICAL, filePath,
                        call.getBegin().map(p -> p.line).orElse(0), call.toString(),
                        Set.of(Framework.PCI_DSS, Framework.HIPAA, Framework.SOC2, Framework.ISO_27001),
                        "ECB mode detected in cipher transformation. ECB does not provide semantic security.",
                        "Use CBC or GCM mode instead (e.g., AES/GCM/NoPadding)."));
                }
            }
        });
        return violations;
    }
}
```

- [ ] **Step 5: Implement WeakTlsRule**

```java
package com.vigil.rules.encryption;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.vigil.rules.*;
import java.util.*;

public class WeakTlsRule implements Rule {
    private static final Set<String> WEAK_PROTOCOLS = Set.of("SSL", "SSLv2", "SSLv3", "TLSv1", "TLSv1.1");

    @Override public String getId() { return "VIGIL-ENC-003"; }
    @Override public String getName() { return "Weak TLS/SSL Protocol"; }
    @Override public RuleCategory getCategory() { return RuleCategory.ENCRYPTION; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(MethodCallExpr.class).forEach(call -> {
            if (call.getNameAsString().equals("getInstance")
                    && call.getScope().isPresent()
                    && call.getScope().get().toString().equals("SSLContext")
                    && !call.getArguments().isEmpty()
                    && call.getArgument(0).isStringLiteralExpr()) {
                String protocol = call.getArgument(0).asStringLiteralExpr().getValue();
                if (WEAK_PROTOCOLS.contains(protocol)) {
                    violations.add(new Violation(getId(), getName(), getCategory(), Severity.CRITICAL, filePath,
                        call.getBegin().map(p -> p.line).orElse(0), call.toString(),
                        Set.of(Framework.PCI_DSS, Framework.HIPAA, Framework.SOC2, Framework.ISO_27001),
                        "Weak TLS/SSL protocol '" + protocol + "' detected.",
                        "Use TLSv1.2 or TLSv1.3. PCI DSS requires TLS 1.2 minimum."));
                }
            }
        });
        return violations;
    }
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=EncryptionRulesTest -q`

Expected: Tests run: 8, Failures: 0

- [ ] **Step 7: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add encryption rules (weak hash, weak cipher, weak TLS)"
```

---

### Task 7: PII Detection Utility and PII Rules

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/rules/PiiFieldDetector.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/pii/PiiInLogsRule.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/pii/PiiInCookiesRule.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/pii/UnmaskedPiiResponseRule.java`
- Test: `vigil-core/src/test/java/com/vigil/rules/pii/PiiRulesTest.java`

- [ ] **Step 1: Write failing tests**

```java
package com.vigil.rules.pii;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.*;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class PiiRulesTest {
    private CompilationUnit parse(String source) {
        return new JavaParser().parse(source).getResult().orElseThrow();
    }

    @Test
    void shouldDetectPiiInLoggerInfo() {
        CompilationUnit cu = parse("public class U { private org.slf4j.Logger logger; void p(String email) { logger.info(\"User: \" + email); } }");
        List<Violation> v = new PiiInLogsRule().check(cu, "U.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).ruleId()).isEqualTo("VIGIL-PII-001");
        assertThat(v.get(0).frameworks()).contains(Framework.GDPR, Framework.HIPAA);
    }

    @Test
    void shouldDetectSsnInLogger() {
        CompilationUnit cu = parse("public class P { private org.slf4j.Logger log; void l(String ssn) { log.debug(\"SSN: \" + ssn); } }");
        List<Violation> v = new PiiInLogsRule().check(cu, "P.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).severity()).isEqualTo(Severity.CRITICAL);
    }

    @Test
    void shouldNotFlagNonPiiInLogs() {
        CompilationUnit cu = parse("public class O { private org.slf4j.Logger logger; void p(String orderId) { logger.info(\"Order: \" + orderId); } }");
        assertThat(new PiiInLogsRule().check(cu, "O.java")).isEmpty();
    }

    @Test
    void shouldDetectPiiInCookieValue() {
        CompilationUnit cu = parse("import javax.servlet.http.Cookie; public class A { void l(String email) { Cookie c = new Cookie(\"e\", email); } }");
        List<Violation> v = new PiiInCookiesRule().check(cu, "A.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).ruleId()).isEqualTo("VIGIL-PII-002");
    }

    @Test
    void shouldDetectPiiInResponseBody() {
        CompilationUnit cu = parse("import org.springframework.web.bind.annotation.*; @RestController public class UC { @GetMapping(\"/u\") public String g() { String ssn = getSsn(); return ssn; } String getSsn() { return \"\"; } }");
        List<Violation> v = new UnmaskedPiiResponseRule().check(cu, "UC.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).ruleId()).isEqualTo("VIGIL-PII-003");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=PiiRulesTest -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement PiiFieldDetector**

```java
package com.vigil.rules;

import java.util.Set;
import java.util.regex.Pattern;

public class PiiFieldDetector {
    private static final Set<String> CRITICAL_PII = Set.of(
        "ssn", "socialsecuritynumber", "socialsecurity", "taxid",
        "healthrecord", "medicalrecord", "diagnosis", "patient");

    private static final Pattern PII_PATTERN = Pattern.compile(
        ".*(email|e_mail|phone|phonenumber|phone_number|mobile|address|street|"
        + "zipcode|zip_code|postalcode|postal_code|dateofbirth|date_of_birth|dob|birthdate|"
        + "firstname|first_name|lastname|last_name|fullname|full_name|"
        + "ssn|social_security|socialsecurity|taxid|tax_id|"
        + "creditcard|credit_card|cardnumber|card_number|cvv|"
        + "passport|driver_license|driverlicense|"
        + "healthrecord|medicalrecord|diagnosis|patient).*", Pattern.CASE_INSENSITIVE);

    public static boolean isPiiName(String name) { return PII_PATTERN.matcher(name).matches(); }

    public static boolean isCriticalPii(String name) {
        String normalized = name.toLowerCase().replaceAll("[_\\-]", "");
        return CRITICAL_PII.stream().anyMatch(normalized::contains);
    }

    public static Severity getSeverity(String name) {
        return isCriticalPii(name) ? Severity.CRITICAL : Severity.HIGH;
    }
}
```

- [ ] **Step 4: Implement PiiInLogsRule**

```java
package com.vigil.rules.pii;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.vigil.rules.*;
import java.util.*;

public class PiiInLogsRule implements Rule {
    private static final Set<String> LOG_METHODS = Set.of("info", "debug", "warn", "error", "trace", "log", "println");

    @Override public String getId() { return "VIGIL-PII-001"; }
    @Override public String getName() { return "PII in Log Statements"; }
    @Override public RuleCategory getCategory() { return RuleCategory.PII; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(MethodCallExpr.class).forEach(call -> {
            if (!LOG_METHODS.contains(call.getNameAsString())) return;
            call.getArguments().forEach(arg -> {
                arg.findAll(NameExpr.class).forEach(name -> {
                    if (PiiFieldDetector.isPiiName(name.getNameAsString())) {
                        violations.add(new Violation(getId(), getName(), getCategory(),
                            PiiFieldDetector.getSeverity(name.getNameAsString()), filePath,
                            call.getBegin().map(p -> p.line).orElse(0), call.toString(),
                            Set.of(Framework.GDPR, Framework.HIPAA, Framework.CCPA, Framework.LGPD, Framework.POPIA),
                            "PII field '" + name.getNameAsString() + "' is being logged.",
                            "Remove PII from log statements, or mask/hash the data before logging."));
                    }
                });
            });
        });
        return violations;
    }
}
```

- [ ] **Step 5: Implement PiiInCookiesRule**

```java
package com.vigil.rules.pii;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.vigil.rules.*;
import java.util.*;

public class PiiInCookiesRule implements Rule {
    @Override public String getId() { return "VIGIL-PII-002"; }
    @Override public String getName() { return "PII Stored in Cookies"; }
    @Override public RuleCategory getCategory() { return RuleCategory.PII; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(ObjectCreationExpr.class).forEach(creation -> {
            if (creation.getType().getNameAsString().equals("Cookie") && creation.getArguments().size() >= 2) {
                creation.getArgument(1).findAll(NameExpr.class).forEach(name -> {
                    if (PiiFieldDetector.isPiiName(name.getNameAsString())) {
                        violations.add(new Violation(getId(), getName(), getCategory(),
                            PiiFieldDetector.getSeverity(name.getNameAsString()), filePath,
                            creation.getBegin().map(p -> p.line).orElse(0), creation.toString(),
                            Set.of(Framework.GDPR, Framework.HIPAA, Framework.CCPA, Framework.POPIA),
                            "PII field '" + name.getNameAsString() + "' is being stored in a cookie.",
                            "Do not store PII in cookies. Use server-side sessions with a session ID cookie instead."));
                    }
                });
            }
        });
        return violations;
    }
}
```

- [ ] **Step 6: Implement UnmaskedPiiResponseRule**

```java
package com.vigil.rules.pii;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.vigil.rules.*;
import java.util.*;

public class UnmaskedPiiResponseRule implements Rule {
    @Override public String getId() { return "VIGIL-PII-003"; }
    @Override public String getName() { return "Unmasked PII in API Response"; }
    @Override public RuleCategory getCategory() { return RuleCategory.PII; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(clazz -> {
            boolean isController = clazz.getAnnotations().stream()
                .anyMatch(a -> a.getNameAsString().equals("RestController") || a.getNameAsString().equals("Controller"));
            if (!isController) return;
            clazz.findAll(MethodDeclaration.class).forEach(method -> {
                boolean isEndpoint = method.getAnnotations().stream()
                    .anyMatch(a -> Set.of("GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "RequestMapping")
                        .contains(a.getNameAsString()));
                if (!isEndpoint) return;
                method.findAll(ReturnStmt.class).forEach(ret -> ret.getExpression().ifPresent(expr ->
                    expr.findAll(NameExpr.class).forEach(name -> {
                        if (PiiFieldDetector.isPiiName(name.getNameAsString())) {
                            violations.add(new Violation(getId(), getName(), getCategory(),
                                PiiFieldDetector.getSeverity(name.getNameAsString()), filePath,
                                ret.getBegin().map(p -> p.line).orElse(0), ret.toString(),
                                Set.of(Framework.GDPR, Framework.HIPAA, Framework.CCPA, Framework.POPIA),
                                "PII field '" + name.getNameAsString() + "' returned in API response without masking.",
                                "Mask or redact PII before returning in API responses. Use DTOs with masked fields."));
                        }
                    })
                ));
            });
        });
        return violations;
    }
}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=PiiRulesTest -q`

Expected: Tests run: 5, Failures: 0

- [ ] **Step 8: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add PII detection rules (logs, cookies, API responses)"
```

---

### Task 8: Logging Compliance Rules

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/rules/logging/SensitiveDataInLogsRule.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/logging/MissingAuditLogRule.java`
- Test: `vigil-core/src/test/java/com/vigil/rules/logging/LoggingRulesTest.java`

- [ ] **Step 1: Write failing tests**

```java
package com.vigil.rules.logging;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.*;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class LoggingRulesTest {
    private CompilationUnit parse(String source) {
        return new JavaParser().parse(source).getResult().orElseThrow();
    }

    @Test
    void shouldDetectPasswordInLogs() {
        CompilationUnit cu = parse("public class A { private org.slf4j.Logger logger; void l(String password) { logger.info(\"pw: \" + password); } }");
        List<Violation> v = new SensitiveDataInLogsRule().check(cu, "A.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).ruleId()).isEqualTo("VIGIL-LOG-001");
    }

    @Test
    void shouldDetectCreditCardInLogs() {
        CompilationUnit cu = parse("public class P { private org.slf4j.Logger log; void c(String creditCardNumber) { log.debug(\"Card: \" + creditCardNumber); } }");
        assertThat(new SensitiveDataInLogsRule().check(cu, "P.java")).hasSize(1);
    }

    @Test
    void shouldFlagAuthMethodWithoutLogging() {
        CompilationUnit cu = parse("public class A { void login(String u, String p) { validate(u, p); } boolean validate(String u, String p) { return true; } }");
        List<Violation> v = new MissingAuditLogRule().check(cu, "A.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).ruleId()).isEqualTo("VIGIL-LOG-002");
        assertThat(v.get(0).severity()).isEqualTo(Severity.MEDIUM);
    }

    @Test
    void shouldNotFlagMethodWithLogging() {
        CompilationUnit cu = parse("public class A { private org.slf4j.Logger logger; void login(String u) { logger.info(\"attempt: \" + u); } }");
        assertThat(new MissingAuditLogRule().check(cu, "A.java")).isEmpty();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=LoggingRulesTest -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement SensitiveDataInLogsRule**

```java
package com.vigil.rules.logging;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.vigil.rules.*;
import java.util.*;
import java.util.regex.Pattern;

public class SensitiveDataInLogsRule implements Rule {
    private static final Set<String> LOG_METHODS = Set.of("info", "debug", "warn", "error", "trace", "log");
    private static final Pattern SENSITIVE_PATTERN = Pattern.compile(
        ".*(password|passwd|pwd|secret|credential|creditcard|credit_card|cardnumber|card_number|cvv|cvc|pin|privatekey|private_key).*",
        Pattern.CASE_INSENSITIVE);

    @Override public String getId() { return "VIGIL-LOG-001"; }
    @Override public String getName() { return "Sensitive Data in Logs"; }
    @Override public RuleCategory getCategory() { return RuleCategory.LOGGING; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(MethodCallExpr.class).forEach(call -> {
            if (!LOG_METHODS.contains(call.getNameAsString())) return;
            call.getArguments().forEach(arg -> arg.findAll(NameExpr.class).forEach(name -> {
                if (SENSITIVE_PATTERN.matcher(name.getNameAsString()).matches()) {
                    violations.add(new Violation(getId(), getName(), getCategory(), Severity.HIGH, filePath,
                        call.getBegin().map(p -> p.line).orElse(0), call.toString(),
                        Set.of(Framework.SOC2, Framework.HIPAA, Framework.PCI_DSS, Framework.GDPR),
                        "Sensitive field '" + name.getNameAsString() + "' is being logged.",
                        "Never log passwords, credit card numbers, or other secrets. Remove or redact before logging."));
                }
            }));
        });
        return violations;
    }
}
```

- [ ] **Step 4: Implement MissingAuditLogRule**

```java
package com.vigil.rules.logging;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.vigil.rules.*;
import java.util.*;
import java.util.regex.Pattern;

public class MissingAuditLogRule implements Rule {
    private static final Pattern AUDIT_METHOD_PATTERN = Pattern.compile(
        ".*(login|logout|authenticate|authorize|changePassword|change_password|resetPassword|reset_password|"
        + "grantRole|grant_role|revokeRole|revoke_role|deleteUser|delete_user|updatePermission|update_permission).*",
        Pattern.CASE_INSENSITIVE);
    private static final Set<String> LOG_METHODS = Set.of("info", "debug", "warn", "error", "trace", "log");

    @Override public String getId() { return "VIGIL-LOG-002"; }
    @Override public String getName() { return "Missing Audit Log"; }
    @Override public RuleCategory getCategory() { return RuleCategory.LOGGING; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(MethodDeclaration.class).forEach(method -> {
            if (!AUDIT_METHOD_PATTERN.matcher(method.getNameAsString()).matches()) return;
            if (method.getBody().isEmpty()) return;
            boolean hasLogCall = method.findAll(MethodCallExpr.class).stream()
                .anyMatch(call -> LOG_METHODS.contains(call.getNameAsString()));
            if (!hasLogCall) {
                violations.add(new Violation(getId(), getName(), getCategory(), Severity.MEDIUM, filePath,
                    method.getBegin().map(p -> p.line).orElse(0), method.getDeclarationAsString(),
                    Set.of(Framework.SOC2, Framework.HIPAA, Framework.PCI_DSS, Framework.GDPR),
                    "Security-critical method '" + method.getNameAsString() + "' has no audit logging.",
                    "Add logging for authentication, authorization, and privilege changes to maintain an audit trail."));
            }
        });
        return violations;
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=LoggingRulesTest -q`

Expected: Tests run: 4, Failures: 0

- [ ] **Step 6: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add logging compliance rules (sensitive data, audit logging)"
```

---

### Task 9: Storage Rules

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/rules/storage/InsecureCookieRule.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/storage/UnencryptedFileWriteRule.java`
- Test: `vigil-core/src/test/java/com/vigil/rules/storage/StorageRulesTest.java`

- [ ] **Step 1: Write failing tests**

```java
package com.vigil.rules.storage;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.*;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class StorageRulesTest {
    private CompilationUnit parse(String source) {
        return new JavaParser().parse(source).getResult().orElseThrow();
    }

    @Test
    void shouldDetectCookieWithoutSecureFlag() {
        CompilationUnit cu = parse("import javax.servlet.http.Cookie; public class W { void s() { Cookie c = new Cookie(\"s\", \"v\"); c.setHttpOnly(true); } }");
        List<Violation> v = new InsecureCookieRule().check(cu, "W.java");
        assertThat(v).isNotEmpty();
        assertThat(v.get(0).ruleId()).isEqualTo("VIGIL-STO-001");
    }

    @Test
    void shouldPassWhenCookieIsFullySecured() {
        CompilationUnit cu = parse("import javax.servlet.http.Cookie; public class W { void s() { Cookie c = new Cookie(\"s\", \"v\"); c.setSecure(true); c.setHttpOnly(true); } }");
        assertThat(new InsecureCookieRule().check(cu, "W.java")).isEmpty();
    }

    @Test
    void shouldDetectPiiWrittenToFile() {
        CompilationUnit cu = parse("import java.io.FileWriter; public class E { void e(String email) throws Exception { FileWriter fw = new FileWriter(\"u.csv\"); fw.write(email); } }");
        List<Violation> v = new UnencryptedFileWriteRule().check(cu, "E.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).ruleId()).isEqualTo("VIGIL-STO-002");
    }

    @Test
    void shouldNotFlagNonPiiFileWrite() {
        CompilationUnit cu = parse("import java.io.FileWriter; public class L { void e(String logLine) throws Exception { FileWriter fw = new FileWriter(\"a.log\"); fw.write(logLine); } }");
        assertThat(new UnencryptedFileWriteRule().check(cu, "L.java")).isEmpty();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=StorageRulesTest -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement InsecureCookieRule**

```java
package com.vigil.rules.storage;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.vigil.rules.*;
import java.util.*;

public class InsecureCookieRule implements Rule {
    @Override public String getId() { return "VIGIL-STO-001"; }
    @Override public String getName() { return "Insecure Cookie Configuration"; }
    @Override public RuleCategory getCategory() { return RuleCategory.STORAGE; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(MethodDeclaration.class).forEach(method -> {
            List<ObjectCreationExpr> cookies = method.findAll(ObjectCreationExpr.class).stream()
                .filter(c -> c.getType().getNameAsString().equals("Cookie")).toList();
            for (ObjectCreationExpr cookie : cookies) {
                List<MethodCallExpr> calls = method.findAll(MethodCallExpr.class);
                boolean hasSecure = calls.stream().anyMatch(c -> c.getNameAsString().equals("setSecure"));
                boolean hasHttpOnly = calls.stream().anyMatch(c -> c.getNameAsString().equals("setHttpOnly"));
                List<String> missing = new ArrayList<>();
                if (!hasSecure) missing.add("Secure");
                if (!hasHttpOnly) missing.add("HttpOnly");
                if (!missing.isEmpty()) {
                    violations.add(new Violation(getId(), getName(), getCategory(), Severity.HIGH, filePath,
                        cookie.getBegin().map(p -> p.line).orElse(0), cookie.toString(),
                        Set.of(Framework.GDPR, Framework.HIPAA, Framework.PCI_DSS, Framework.SOC2),
                        "Cookie created without " + String.join(" and ", missing) + " flag(s).",
                        "Set cookie.setSecure(true) and cookie.setHttpOnly(true). Consider SameSite=Strict."));
                }
            }
        });
        return violations;
    }
}
```

- [ ] **Step 4: Implement UnencryptedFileWriteRule**

```java
package com.vigil.rules.storage;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.vigil.rules.*;
import java.util.*;

public class UnencryptedFileWriteRule implements Rule {
    private static final Set<String> WRITE_METHODS = Set.of("write", "append", "writeString", "println", "print");

    @Override public String getId() { return "VIGIL-STO-002"; }
    @Override public String getName() { return "Unencrypted PII File Write"; }
    @Override public RuleCategory getCategory() { return RuleCategory.STORAGE; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(MethodCallExpr.class).forEach(call -> {
            if (!WRITE_METHODS.contains(call.getNameAsString())) return;
            call.getArguments().forEach(arg -> arg.findAll(NameExpr.class).forEach(name -> {
                if (PiiFieldDetector.isPiiName(name.getNameAsString())) {
                    violations.add(new Violation(getId(), getName(), getCategory(), Severity.HIGH, filePath,
                        call.getBegin().map(p -> p.line).orElse(0), call.toString(),
                        Set.of(Framework.GDPR, Framework.HIPAA, Framework.PCI_DSS, Framework.SOC2),
                        "PII field '" + name.getNameAsString() + "' written to file without encryption.",
                        "Encrypt sensitive data before writing to files. Use AES-256-GCM or similar."));
                }
            }));
        });
        return violations;
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=StorageRulesTest -q`

Expected: Tests run: 4, Failures: 0

- [ ] **Step 6: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add storage rules (insecure cookies, unencrypted PII file writes)"
```

---

### Task 10: Access Control Rules

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/rules/accesscontrol/UnauthenticatedEndpointRule.java`
- Create: `vigil-core/src/main/java/com/vigil/rules/accesscontrol/MissingAuthMiddlewareRule.java`
- Test: `vigil-core/src/test/java/com/vigil/rules/accesscontrol/AccessControlRulesTest.java`

- [ ] **Step 1: Write failing tests**

```java
package com.vigil.rules.accesscontrol;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.*;
import org.junit.jupiter.api.Test;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class AccessControlRulesTest {
    private CompilationUnit parse(String source) {
        return new JavaParser().parse(source).getResult().orElseThrow();
    }

    @Test
    void shouldFlagEndpointWithoutSecurityAnnotation() {
        CompilationUnit cu = parse("import org.springframework.web.bind.annotation.*; @RestController public class U { @GetMapping(\"/u\") public String g() { return \"u\"; } }");
        List<Violation> v = new UnauthenticatedEndpointRule().check(cu, "U.java");
        assertThat(v).hasSize(1);
        assertThat(v.get(0).ruleId()).isEqualTo("VIGIL-AC-001");
        assertThat(v.get(0).severity()).isEqualTo(Severity.HIGH);
    }

    @Test
    void shouldNotFlagEndpointWithPreAuthorize() {
        CompilationUnit cu = parse("import org.springframework.web.bind.annotation.*; import org.springframework.security.access.prepost.PreAuthorize; @RestController public class U { @GetMapping(\"/u\") @PreAuthorize(\"hasRole('ADMIN')\") public String g() { return \"u\"; } }");
        assertThat(new UnauthenticatedEndpointRule().check(cu, "U.java")).isEmpty();
    }

    @Test
    void shouldNotFlagEndpointWithRolesAllowed() {
        CompilationUnit cu = parse("import org.springframework.web.bind.annotation.*; import javax.annotation.security.RolesAllowed; @RestController public class U { @GetMapping(\"/u\") @RolesAllowed(\"ADMIN\") public String g() { return \"u\"; } }");
        assertThat(new UnauthenticatedEndpointRule().check(cu, "U.java")).isEmpty();
    }

    @Test
    void shouldNotFlagClassWithClassLevelSecurity() {
        CompilationUnit cu = parse("import org.springframework.web.bind.annotation.*; import org.springframework.security.access.prepost.PreAuthorize; @RestController @PreAuthorize(\"isAuthenticated()\") public class U { @GetMapping(\"/u\") public String g() { return \"u\"; } }");
        assertThat(new UnauthenticatedEndpointRule().check(cu, "U.java")).isEmpty();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=AccessControlRulesTest -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement UnauthenticatedEndpointRule**

```java
package com.vigil.rules.accesscontrol;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.vigil.rules.*;
import java.util.*;

public class UnauthenticatedEndpointRule implements Rule {
    private static final Set<String> ENDPOINT_ANNOTATIONS = Set.of(
        "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping");
    private static final Set<String> SECURITY_ANNOTATIONS = Set.of(
        "PreAuthorize", "PostAuthorize", "Secured", "RolesAllowed", "PermitAll", "DenyAll");

    @Override public String getId() { return "VIGIL-AC-001"; }
    @Override public String getName() { return "Unauthenticated Endpoint"; }
    @Override public RuleCategory getCategory() { return RuleCategory.ACCESS_CONTROL; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();
        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(clazz -> {
            boolean isController = clazz.getAnnotations().stream()
                .anyMatch(a -> a.getNameAsString().equals("RestController") || a.getNameAsString().equals("Controller"));
            if (!isController) return;
            boolean hasClassSecurity = clazz.getAnnotations().stream()
                .anyMatch(a -> SECURITY_ANNOTATIONS.contains(a.getNameAsString()));
            if (hasClassSecurity) return;
            clazz.findAll(MethodDeclaration.class).forEach(method -> {
                boolean isEndpoint = method.getAnnotations().stream()
                    .anyMatch(a -> ENDPOINT_ANNOTATIONS.contains(a.getNameAsString()));
                if (!isEndpoint) return;
                boolean hasMethodSecurity = method.getAnnotations().stream()
                    .anyMatch(a -> SECURITY_ANNOTATIONS.contains(a.getNameAsString()));
                if (!hasMethodSecurity) {
                    violations.add(new Violation(getId(), getName(), getCategory(), Severity.HIGH, filePath,
                        method.getBegin().map(p -> p.line).orElse(0), method.getDeclarationAsString(),
                        Set.of(Framework.SOC2, Framework.PCI_DSS, Framework.HIPAA, Framework.ISO_27001),
                        "Endpoint '" + method.getNameAsString() + "' has no authentication/authorization annotation.",
                        "Add @PreAuthorize, @Secured, or @RolesAllowed. If intentionally public, add @PermitAll."));
                }
            });
        });
        return violations;
    }
}
```

- [ ] **Step 4: Create MissingAuthMiddlewareRule (JS-specific, no-op for Java)**

```java
package com.vigil.rules.accesscontrol;

import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.*;
import java.util.List;

public class MissingAuthMiddlewareRule implements Rule {
    @Override public String getId() { return "VIGIL-AC-002"; }
    @Override public String getName() { return "Missing Auth Middleware"; }
    @Override public RuleCategory getCategory() { return RuleCategory.ACCESS_CONTROL; }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        return List.of(); // JS/TS Express-specific — no-op for Java AST
    }
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=AccessControlRulesTest -q`

Expected: Tests run: 4, Failures: 0

- [ ] **Step 6: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add access control rules (unauthenticated endpoints)"
```

---

### Task 11: Dependency Analysis

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/dependencies/DependencyInfo.java`
- Create: `vigil-core/src/main/java/com/vigil/dependencies/MavenPomParser.java`
- Create: `vigil-core/src/main/java/com/vigil/dependencies/NpmPackageParser.java`
- Create: `vigil-core/src/main/java/com/vigil/dependencies/OsvClient.java`
- Create: `vigil-core/src/main/java/com/vigil/dependencies/DependencyAnalyzer.java`
- Test: `vigil-core/src/test/java/com/vigil/dependencies/MavenPomParserTest.java`
- Test: `vigil-core/src/test/java/com/vigil/dependencies/NpmPackageParserTest.java`

- [ ] **Step 1: Write failing tests**

`MavenPomParserTest.java`:
```java
package com.vigil.dependencies;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class MavenPomParserTest {
    @TempDir Path tempDir;

    @Test
    void shouldParseDependenciesFromPom() throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
            <?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
            <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>
            <dependencies>
              <dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency>
              <dependency><groupId>com.google.guava</groupId><artifactId>guava</artifactId><version>31.1-jre</version></dependency>
            </dependencies></project>""");
        List<DependencyInfo> deps = new MavenPomParser().parse(tempDir.resolve("pom.xml"));
        assertThat(deps).hasSize(2);
        assertThat(deps.get(0).groupId()).isEqualTo("org.apache.logging.log4j");
        assertThat(deps.get(0).artifactId()).isEqualTo("log4j-core");
        assertThat(deps.get(0).version()).isEqualTo("2.14.1");
    }

    @Test
    void shouldHandlePomWithNoDependencies() throws IOException {
        Files.writeString(tempDir.resolve("pom.xml"), """
            <?xml version="1.0"?><project><modelVersion>4.0.0</modelVersion>
            <groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version></project>""");
        assertThat(new MavenPomParser().parse(tempDir.resolve("pom.xml"))).isEmpty();
    }
}
```

`NpmPackageParserTest.java`:
```java
package com.vigil.dependencies;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class NpmPackageParserTest {
    @TempDir Path tempDir;

    @Test
    void shouldParseDependenciesFromPackageJson() throws IOException {
        Files.writeString(tempDir.resolve("package.json"), """
            {"name":"app","version":"1.0.0","dependencies":{"lodash":"4.17.20","express":"^4.18.2"},"devDependencies":{"jest":"^29.0.0"}}""");
        List<DependencyInfo> deps = new NpmPackageParser().parse(tempDir.resolve("package.json"));
        assertThat(deps).hasSize(3);
        assertThat(deps).anyMatch(d -> d.artifactId().equals("lodash") && d.version().equals("4.17.20"));
    }

    @Test
    void shouldHandleEmptyPackageJson() throws IOException {
        Files.writeString(tempDir.resolve("package.json"), "{}");
        assertThat(new NpmPackageParser().parse(tempDir.resolve("package.json"))).isEmpty();
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest="MavenPomParserTest,NpmPackageParserTest" -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement DependencyInfo, MavenPomParser, NpmPackageParser, OsvClient, DependencyAnalyzer**

`DependencyInfo.java`:
```java
package com.vigil.dependencies;

public record DependencyInfo(String groupId, String artifactId, String version, String ecosystem) {}
```

`MavenPomParser.java`:
```java
package com.vigil.dependencies;

import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.*;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class MavenPomParser {
    public List<DependencyInfo> parse(Path pomPath) {
        List<DependencyInfo> deps = new ArrayList<>();
        try {
            Document doc = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(pomPath.toFile());
            doc.getDocumentElement().normalize();
            NodeList depNodes = doc.getElementsByTagName("dependency");
            for (int i = 0; i < depNodes.getLength(); i++) {
                Element dep = (Element) depNodes.item(i);
                String gId = getText(dep, "groupId"), aId = getText(dep, "artifactId"), ver = getText(dep, "version");
                if (gId != null && aId != null && ver != null)
                    deps.add(new DependencyInfo(gId, aId, ver, "Maven"));
            }
        } catch (Exception e) { /* skip unparseable */ }
        return deps;
    }
    private String getText(Element parent, String tag) {
        NodeList n = parent.getElementsByTagName(tag);
        return n.getLength() > 0 ? n.item(0).getTextContent().trim() : null;
    }
}
```

`NpmPackageParser.java`:
```java
package com.vigil.dependencies;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.file.Path;
import java.util.*;

public class NpmPackageParser {
    private final ObjectMapper mapper = new ObjectMapper();

    public List<DependencyInfo> parse(Path packageJsonPath) {
        List<DependencyInfo> deps = new ArrayList<>();
        try {
            JsonNode root = mapper.readTree(packageJsonPath.toFile());
            addDeps(root.get("dependencies"), deps);
            addDeps(root.get("devDependencies"), deps);
        } catch (Exception e) { /* skip */ }
        return deps;
    }
    private void addDeps(JsonNode node, List<DependencyInfo> deps) {
        if (node == null || !node.isObject()) return;
        node.fields().forEachRemaining(e -> {
            String version = e.getValue().asText().replaceAll("^[~^>=<]+", "");
            deps.add(new DependencyInfo("npm", e.getKey(), version, "npm"));
        });
    }
}
```

`OsvClient.java`:
```java
package com.vigil.dependencies;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.vigil.rules.Severity;
import java.net.URI;
import java.net.http.*;
import java.time.Duration;
import java.util.*;

public class OsvClient {
    private static final String OSV_API_URL = "https://api.osv.dev/v1/query";
    private final HttpClient httpClient;
    private final ObjectMapper mapper = new ObjectMapper();

    public OsvClient() { this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build(); }
    public OsvClient(HttpClient httpClient) { this.httpClient = httpClient; }

    public record VulnerabilityInfo(String id, String summary, Severity severity) {}

    public List<VulnerabilityInfo> queryVulnerabilities(DependencyInfo dep) {
        List<VulnerabilityInfo> vulns = new ArrayList<>();
        try {
            String eco = dep.ecosystem().equals("Maven") ? "Maven" : "npm";
            String pkg = dep.ecosystem().equals("Maven") ? dep.groupId() + ":" + dep.artifactId() : dep.artifactId();
            String body = mapper.writeValueAsString(Map.of("package", Map.of("name", pkg, "ecosystem", eco), "version", dep.version()));
            HttpRequest req = HttpRequest.newBuilder().uri(URI.create(OSV_API_URL))
                .header("Content-Type", "application/json").POST(HttpRequest.BodyPublishers.ofString(body)).build();
            HttpResponse<String> resp = httpClient.send(req, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() == 200) {
                JsonNode root = mapper.readTree(resp.body());
                JsonNode arr = root.get("vulns");
                if (arr != null && arr.isArray()) {
                    for (JsonNode v : arr) {
                        vulns.add(new VulnerabilityInfo(
                            v.has("id") ? v.get("id").asText() : "UNKNOWN",
                            v.has("summary") ? v.get("summary").asText() : "No description",
                            extractSeverity(v)));
                    }
                }
            }
        } catch (Exception e) { /* network error — skip */ }
        return vulns;
    }
    private Severity extractSeverity(JsonNode vuln) {
        if (vuln.has("database_specific")) {
            JsonNode db = vuln.get("database_specific");
            if (db.has("severity")) {
                return switch (db.get("severity").asText().toUpperCase()) {
                    case "CRITICAL" -> Severity.CRITICAL; case "HIGH" -> Severity.HIGH;
                    case "MODERATE", "MEDIUM" -> Severity.MEDIUM; default -> Severity.LOW;
                };
            }
        }
        return Severity.MEDIUM;
    }
}
```

`DependencyAnalyzer.java`:
```java
package com.vigil.dependencies;

import com.vigil.rules.*;
import java.nio.file.Path;
import java.util.*;

public class DependencyAnalyzer {
    private final MavenPomParser mavenParser = new MavenPomParser();
    private final NpmPackageParser npmParser = new NpmPackageParser();
    private final OsvClient osvClient;

    public DependencyAnalyzer() { this.osvClient = new OsvClient(); }
    public DependencyAnalyzer(OsvClient osvClient) { this.osvClient = osvClient; }

    public List<Violation> analyze(List<Path> manifests) {
        List<Violation> violations = new ArrayList<>();
        List<DependencyInfo> allDeps = new ArrayList<>();
        for (Path m : manifests) {
            if (m.getFileName().toString().equals("pom.xml")) allDeps.addAll(mavenParser.parse(m));
            else if (m.getFileName().toString().equals("package.json")) allDeps.addAll(npmParser.parse(m));
        }
        for (DependencyInfo dep : allDeps) {
            for (OsvClient.VulnerabilityInfo v : osvClient.queryVulnerabilities(dep)) {
                violations.add(new Violation("VIGIL-DEP-001", "Known Vulnerability in Dependency",
                    RuleCategory.DEPENDENCIES, v.severity(),
                    dep.ecosystem().equals("Maven") ? "pom.xml" : "package.json", 0,
                    dep.groupId() + ":" + dep.artifactId() + ":" + dep.version(),
                    Set.of(Framework.SOC2, Framework.PCI_DSS, Framework.ISO_27001),
                    v.id() + ": " + v.summary() + " in " + dep.artifactId() + " " + dep.version(),
                    "Update " + dep.artifactId() + " to the latest patched version."));
            }
        }
        return violations;
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest="MavenPomParserTest,NpmPackageParserTest" -q`

Expected: Tests run: 4, Failures: 0

- [ ] **Step 5: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add dependency analysis (POM/package.json parsing, OSV CVE lookup)"
```

---

### Task 12: Scanner Orchestrator and Vigil Facade

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/scanner/Scanner.java`
- Create: `vigil-core/src/main/java/com/vigil/Vigil.java`
- Create: `vigil-core/src/main/java/com/vigil/report/ReportData.java`
- Test: `vigil-core/src/test/java/com/vigil/scanner/ScannerTest.java`

- [ ] **Step 1: Write failing test**

```java
package com.vigil.scanner;

import com.vigil.rules.*;
import com.vigil.rules.secrets.HardcodedPasswordRule;
import com.vigil.rules.encryption.WeakHashAlgorithmRule;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import static org.assertj.core.api.Assertions.assertThat;

class ScannerTest {
    @TempDir Path tempDir;

    @Test
    void shouldScanProjectAndFindViolations() throws IOException {
        Files.createDirectories(tempDir.resolve("src"));
        Files.writeString(tempDir.resolve("src/Config.java"), "public class Config { private String password = \"secret123\"; }");
        Files.writeString(tempDir.resolve("src/Hasher.java"), "import java.security.MessageDigest; public class Hasher { void h() throws Exception { MessageDigest.getInstance(\"MD5\"); } }");

        RuleRegistry registry = new RuleRegistry();
        registry.register(new HardcodedPasswordRule());
        registry.register(new WeakHashAlgorithmRule());

        List<Violation> violations = new Scanner(registry).scan(tempDir);
        assertThat(violations).hasSize(2);
        assertThat(violations).anyMatch(v -> v.ruleId().equals("VIGIL-SEC-001"));
        assertThat(violations).anyMatch(v -> v.ruleId().equals("VIGIL-ENC-001"));
    }

    @Test
    void shouldReturnEmptyForCleanProject() throws IOException {
        Files.writeString(tempDir.resolve("App.java"), "public class App { private String name = \"MyApp\"; }");
        RuleRegistry registry = new RuleRegistry();
        registry.register(new HardcodedPasswordRule());
        assertThat(new Scanner(registry).scan(tempDir)).isEmpty();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=ScannerTest -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement Scanner, ReportData, and Vigil facade**

`Scanner.java`:
```java
package com.vigil.scanner;

import com.vigil.rules.RuleRegistry;
import com.vigil.rules.Violation;
import com.vigil.scanner.java.JavaAstScanner;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.stream.Collectors;

public class Scanner {
    private final RuleRegistry registry;
    public Scanner(RuleRegistry registry) { this.registry = registry; }

    public List<Violation> scan(Path projectDir) throws IOException {
        FileDiscovery discovery = new FileDiscovery();
        List<SourceFile> sourceFiles = discovery.discover(projectDir);
        JavaAstScanner javaScanner = new JavaAstScanner(registry);
        return sourceFiles.parallelStream()
            .filter(sf -> sf.language() == Language.JAVA)
            .flatMap(sf -> {
                try {
                    String source = Files.readString(sf.path());
                    String relativePath = projectDir.relativize(sf.path()).toString();
                    return javaScanner.scan(source, relativePath).stream();
                } catch (IOException e) { return java.util.stream.Stream.empty(); }
            })
            .collect(Collectors.toList());
    }
}
```

`ReportData.java`:
```java
package com.vigil.report;

import com.vigil.rules.*;
import java.time.LocalDateTime;
import java.util.*;
import java.util.stream.Collectors;

public class ReportData {
    private final String projectName;
    private final LocalDateTime scanTime;
    private final int filesScanned;
    private final List<Violation> violations;

    public ReportData(String projectName, LocalDateTime scanTime, int filesScanned, List<Violation> violations) {
        this.projectName = projectName; this.scanTime = scanTime;
        this.filesScanned = filesScanned; this.violations = List.copyOf(violations);
    }

    public String getProjectName() { return projectName; }
    public LocalDateTime getScanTime() { return scanTime; }
    public int getFilesScanned() { return filesScanned; }
    public List<Violation> getViolations() { return violations; }
    public int getTotalViolations() { return violations.size(); }
    public Map<Severity, Long> getViolationsBySeverity() { return violations.stream().collect(Collectors.groupingBy(Violation::severity, Collectors.counting())); }
    public Map<RuleCategory, Long> getViolationsByCategory() { return violations.stream().collect(Collectors.groupingBy(Violation::category, Collectors.counting())); }
    public Map<String, List<Violation>> getViolationsByFile() { return violations.stream().collect(Collectors.groupingBy(Violation::filePath)); }
    public Set<Framework> getAffectedFrameworks() { return violations.stream().flatMap(v -> v.frameworks().stream()).collect(Collectors.toSet()); }
}
```

`Vigil.java`:
```java
package com.vigil;

import com.vigil.dependencies.DependencyAnalyzer;
import com.vigil.report.ReportData;
import com.vigil.rules.*;
import com.vigil.rules.accesscontrol.*;
import com.vigil.rules.encryption.*;
import com.vigil.rules.logging.*;
import com.vigil.rules.pii.*;
import com.vigil.rules.secrets.*;
import com.vigil.rules.storage.*;
import com.vigil.scanner.FileDiscovery;
import com.vigil.scanner.Scanner;
import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class Vigil {
    private final RuleRegistry registry;
    private final DependencyAnalyzer dependencyAnalyzer;

    public Vigil() { this.registry = createDefaultRegistry(); this.dependencyAnalyzer = new DependencyAnalyzer(); }
    public Vigil(RuleRegistry registry, DependencyAnalyzer dependencyAnalyzer) { this.registry = registry; this.dependencyAnalyzer = dependencyAnalyzer; }

    public ReportData scan(Path projectDir) throws IOException {
        Scanner scanner = new Scanner(registry);
        List<Violation> violations = new ArrayList<>(scanner.scan(projectDir));
        FileDiscovery discovery = new FileDiscovery();
        violations.addAll(dependencyAnalyzer.analyze(discovery.discoverDependencyManifests(projectDir)));
        return new ReportData(projectDir.getFileName().toString(), LocalDateTime.now(), discovery.discover(projectDir).size(), violations);
    }

    private static RuleRegistry createDefaultRegistry() {
        RuleRegistry r = new RuleRegistry();
        r.register(new HardcodedPasswordRule()); r.register(new HardcodedApiKeyRule()); r.register(new HardcodedTokenRule());
        r.register(new WeakHashAlgorithmRule()); r.register(new WeakCipherRule()); r.register(new WeakTlsRule());
        r.register(new PiiInLogsRule()); r.register(new PiiInCookiesRule()); r.register(new UnmaskedPiiResponseRule());
        r.register(new SensitiveDataInLogsRule()); r.register(new MissingAuditLogRule());
        r.register(new InsecureCookieRule()); r.register(new UnencryptedFileWriteRule());
        r.register(new UnauthenticatedEndpointRule()); r.register(new MissingAuthMiddlewareRule());
        return r;
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=ScannerTest -q`

Expected: Tests run: 2, Failures: 0

- [ ] **Step 5: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add Scanner orchestrator, ReportData, and Vigil facade"
```

---

### Task 13: HTML Report Generator with PatternFly 6

**Files:**
- Create: `vigil-core/src/main/java/com/vigil/report/ReportGenerator.java`
- Create: `vigil-core/src/main/java/com/vigil/report/HtmlReportGenerator.java`
- Create: `vigil-core/src/main/java/com/vigil/report/ConsoleSummaryPrinter.java`
- Create: `vigil-core/src/main/resources/templates/report.mustache`
- Test: `vigil-core/src/test/java/com/vigil/report/HtmlReportGeneratorTest.java`

- [ ] **Step 1: Write failing test**

```java
package com.vigil.report;

import com.vigil.rules.*;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Set;
import static org.assertj.core.api.Assertions.assertThat;

class HtmlReportGeneratorTest {
    @TempDir Path tempDir;

    @Test
    void shouldGenerateHtmlReportFile() throws IOException {
        List<Violation> violations = List.of(
            new Violation("VIGIL-SEC-001", "Hardcoded Password", RuleCategory.SECRETS, Severity.CRITICAL,
                "src/Config.java", 10, "String pwd = \"admin\";", Set.of(Framework.SOC2, Framework.PCI_DSS),
                "Hardcoded password found", "Use env vars"),
            new Violation("VIGIL-ENC-001", "Weak Hash", RuleCategory.ENCRYPTION, Severity.HIGH,
                "src/Hasher.java", 5, "MessageDigest.getInstance(\"MD5\")", Set.of(Framework.PCI_DSS),
                "MD5 is weak", "Use SHA-256"));
        ReportData data = new ReportData("test-project", LocalDateTime.of(2026, 4, 9, 14, 30), 42, violations);
        Path reportPath = new HtmlReportGenerator().generate(data, tempDir.resolve("vigil"));
        assertThat(reportPath).exists();
        String html = Files.readString(reportPath);
        assertThat(html).contains("VIGIL").contains("test-project").contains("VIGIL-SEC-001").contains("pf-v6");
    }

    @Test
    void shouldGenerateEmptyStateForZeroViolations() throws IOException {
        ReportData data = new ReportData("clean-project", LocalDateTime.now(), 10, List.of());
        Path reportPath = new HtmlReportGenerator().generate(data, tempDir.resolve("vigil"));
        assertThat(Files.readString(reportPath)).contains("No violations");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=HtmlReportGeneratorTest -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement ReportGenerator interface, HtmlReportGenerator, ConsoleSummaryPrinter, and the PF6 Mustache template**

`ReportGenerator.java`:
```java
package com.vigil.report;

import java.io.IOException;
import java.nio.file.Path;

public interface ReportGenerator {
    Path generate(ReportData data, Path outputDir) throws IOException;
}
```

`HtmlReportGenerator.java`:
```java
package com.vigil.report;

import com.samskivert.mustache.Mustache;
import com.samskivert.mustache.Template;
import com.vigil.rules.*;
import java.io.*;
import java.nio.file.*;
import java.time.format.DateTimeFormatter;
import java.util.*;

public class HtmlReportGenerator implements ReportGenerator {
    @Override
    public Path generate(ReportData data, Path outputDir) throws IOException {
        Files.createDirectories(outputDir);
        Path reportPath = outputDir.resolve("vigil-report.html");
        try (Reader reader = new InputStreamReader(
                Objects.requireNonNull(getClass().getResourceAsStream("/templates/report.mustache")))) {
            Template template = Mustache.compiler().compile(reader);
            Files.writeString(reportPath, template.execute(buildContext(data)));
        }
        return reportPath;
    }

    private Map<String, Object> buildContext(ReportData data) {
        Map<String, Object> ctx = new HashMap<>();
        ctx.put("projectName", data.getProjectName());
        ctx.put("scanTime", data.getScanTime().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm")));
        ctx.put("filesScanned", data.getFilesScanned());
        ctx.put("totalViolations", data.getTotalViolations());
        ctx.put("hasViolations", data.getTotalViolations() > 0);
        Map<Severity, Long> bySev = data.getViolationsBySeverity();
        ctx.put("criticalCount", bySev.getOrDefault(Severity.CRITICAL, 0L));
        ctx.put("highCount", bySev.getOrDefault(Severity.HIGH, 0L));
        ctx.put("mediumCount", bySev.getOrDefault(Severity.MEDIUM, 0L));
        ctx.put("lowCount", bySev.getOrDefault(Severity.LOW, 0L));
        ctx.put("affectedFrameworks", data.getAffectedFrameworks().stream()
            .map(f -> Map.of("displayName", f.getDisplayName())).toList());
        ctx.put("categories", Arrays.stream(RuleCategory.values())
            .map(c -> Map.of("name", c.name(), "displayName", c.getDisplayName())).toList());
        List<Map<String, Object>> fileGroups = new ArrayList<>();
        data.getViolationsByFile().forEach((file, violations) -> {
            Map<String, Object> group = new HashMap<>();
            group.put("fileName", file);
            group.put("violationCount", violations.size());
            group.put("violations", violations.stream().map(this::violationToMap).toList());
            fileGroups.add(group);
        });
        fileGroups.sort(Comparator.comparing(g -> (String) g.get("fileName")));
        ctx.put("fileGroups", fileGroups);
        return ctx;
    }

    private Map<String, Object> violationToMap(Violation v) {
        Map<String, Object> m = new HashMap<>();
        m.put("ruleId", v.ruleId()); m.put("ruleName", v.ruleName()); m.put("severity", v.severity().name());
        m.put("categoryName", v.category().name()); m.put("lineNumber", v.lineNumber());
        m.put("description", v.description()); m.put("codeSnippet", v.codeSnippet());
        m.put("recommendation", v.recommendation());
        m.put("frameworkList", v.frameworks().stream().map(f -> Map.of("displayName", f.getDisplayName())).toList());
        return m;
    }
}
```

`ConsoleSummaryPrinter.java`:
```java
package com.vigil.report;

import com.vigil.rules.Framework;
import com.vigil.rules.Severity;
import java.io.PrintStream;
import java.util.Map;
import java.util.stream.Collectors;

public class ConsoleSummaryPrinter {
    public void print(ReportData data, String reportPath, PrintStream out) {
        out.println();
        out.println("Vigil Compliance Scan Complete");
        out.println("\u2500".repeat(35));
        out.printf("Files scanned:    %d%n", data.getFilesScanned());
        out.printf("Violations found: %d%n", data.getTotalViolations());
        if (data.getTotalViolations() > 0) {
            Map<Severity, Long> bySev = data.getViolationsBySeverity();
            out.printf("  CRITICAL: %d  |  HIGH: %d  |  MEDIUM: %d  |  LOW: %d%n",
                bySev.getOrDefault(Severity.CRITICAL, 0L), bySev.getOrDefault(Severity.HIGH, 0L),
                bySev.getOrDefault(Severity.MEDIUM, 0L), bySev.getOrDefault(Severity.LOW, 0L));
            out.printf("Frameworks affected: %s%n", data.getAffectedFrameworks().stream()
                .map(Framework::getDisplayName).sorted().collect(Collectors.joining(", ")));
        }
        out.printf("Full report: %s%n%n", reportPath);
    }
}
```

Create the Mustache template at `vigil-core/src/main/resources/templates/report.mustache` — a full PatternFly 6 HTML template. (This is a large file — see the spec for the layout. The template uses PF6 CSS via CDN `https://unpkg.com/@patternfly/patternfly@6/patternfly.min.css`, inlined styles for custom layout, PF6 component class names, Mustache `{{variable}}` and `{{#section}}` syntax, client-side JS for filtering.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=HtmlReportGeneratorTest -q`

Expected: Tests run: 2, Failures: 0

- [ ] **Step 5: Commit**

```bash
git add vigil-core/src/
git commit -m "feat: add HTML report generator with PatternFly 6 template"
```

---

### Task 14: CLI Module

**Files:**
- Create: `vigil-cli/src/main/java/com/vigil/cli/VigilCli.java`
- Test: `vigil-cli/src/test/java/com/vigil/cli/VigilCliTest.java`

- [ ] **Step 1: Write failing test**

```java
package com.vigil.cli;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import static org.assertj.core.api.Assertions.assertThat;

class VigilCliTest {
    @TempDir Path tempDir;

    @Test
    void shouldReturnZeroExitCodeAlways() throws IOException {
        Files.writeString(tempDir.resolve("App.java"), "public class App { private String password = \"secret\"; }");
        VigilCli cli = new VigilCli();
        int exitCode = cli.runScan(tempDir.toString(), tempDir.resolve("output").toString());
        assertThat(exitCode).isEqualTo(0);
        assertThat(tempDir.resolve("output/vigil-report.html")).exists();
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-cli -Dtest=VigilCliTest -q`

Expected: COMPILATION FAILURE

- [ ] **Step 3: Implement VigilCli**

```java
package com.vigil.cli;

import com.vigil.Vigil;
import com.vigil.report.*;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Parameters;
import picocli.CommandLine.Option;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "vigil", mixinStandardHelpOptions = true, version = "Vigil 1.0.0",
    description = "Compliance static analysis for Java and JS/TS projects")
public class VigilCli implements Callable<Integer> {

    @Parameters(index = "0", defaultValue = ".", description = "Project directory to scan")
    private String projectDir;

    @Option(names = {"-o", "--output"}, defaultValue = "target/vigil", description = "Output directory for the report")
    private String outputDir;

    @Override public Integer call() { return runScan(projectDir, outputDir); }

    public int runScan(String projectPath, String outputPath) {
        try {
            Path project = Path.of(projectPath).toAbsolutePath();
            Path output = Path.of(outputPath).toAbsolutePath();
            ReportData data = new Vigil().scan(project);
            Path reportPath = new HtmlReportGenerator().generate(data, output);
            new ConsoleSummaryPrinter().print(data, reportPath.toString(), System.out);
            return 0;
        } catch (Exception e) {
            System.err.println("Vigil scan failed: " + e.getMessage());
            return 0;
        }
    }

    public static void main(String[] args) { System.exit(new CommandLine(new VigilCli()).execute(args)); }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-cli -Dtest=VigilCliTest -q`

Expected: Tests run: 1, Failures: 0

- [ ] **Step 5: Commit**

```bash
git add vigil-cli/src/
git commit -m "feat: add Picocli CLI entry point for Vigil"
```

---

### Task 15: Maven Plugin Module

**Files:**
- Create: `vigil-maven-plugin/src/main/java/com/vigil/maven/VigilMojo.java`

- [ ] **Step 1: Implement VigilMojo**

```java
package com.vigil.maven;

import com.vigil.Vigil;
import com.vigil.report.*;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;
import java.io.IOException;
import java.nio.file.Path;

@Mojo(name = "scan", defaultPhase = LifecyclePhase.VERIFY)
public class VigilMojo extends AbstractMojo {
    @Parameter(defaultValue = "${project.basedir}", readonly = true)
    private String projectDir;

    @Parameter(defaultValue = "${project.build.directory}/vigil")
    private String outputDir;

    @Override
    public void execute() throws MojoExecutionException {
        try {
            Path project = Path.of(projectDir).toAbsolutePath();
            Path output = Path.of(outputDir).toAbsolutePath();
            getLog().info("Vigil: Scanning project for compliance violations...");
            ReportData data = new Vigil().scan(project);
            Path reportPath = new HtmlReportGenerator().generate(data, output);
            new ConsoleSummaryPrinter().print(data, reportPath.toString(), System.out);
        } catch (IOException e) {
            getLog().warn("Vigil scan encountered an error: " + e.getMessage());
        }
    }
}
```

- [ ] **Step 2: Verify it compiles**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn compile -pl vigil-maven-plugin -am -q`

Expected: BUILD SUCCESS

- [ ] **Step 3: Commit**

```bash
git add vigil-maven-plugin/src/
git commit -m "feat: add Maven plugin (VigilMojo) binding to verify phase"
```

---

### Task 16: npm Package Wrapper

**Files:**
- Create: `vigil-npm/package.json`
- Create: `vigil-npm/bin/vigil.js`

- [ ] **Step 1: Create package.json**

```json
{
  "name": "vigil-scan",
  "version": "1.0.0",
  "description": "Compliance static analysis tool for Java and JS/TS projects",
  "bin": { "vigil": "./bin/vigil.js" },
  "keywords": ["compliance", "security", "soc2", "gdpr", "hipaa", "pci-dss", "static-analysis"],
  "license": "Apache-2.0",
  "engines": { "node": ">=16" }
}
```

- [ ] **Step 2: Create vigil.js CLI wrapper**

```javascript
#!/usr/bin/env node

const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');

const jarPath = path.join(__dirname, '..', 'lib', 'vigil-cli.jar');

if (!fs.existsSync(jarPath)) {
    console.error('Error: vigil-cli.jar not found at ' + jarPath);
    process.exit(1);
}

try {
    execFileSync('java', ['-version'], { stdio: 'ignore' });
} catch {
    console.error('Error: Java 17+ is required but not found on PATH.');
    process.exit(1);
}

const projectDir = process.argv[2] || '.';
const outputDir = path.join(process.cwd(), 'vigil-report');

try {
    execFileSync('java', ['-jar', jarPath, projectDir, '-o', outputDir], {
        stdio: 'inherit',
        cwd: process.cwd()
    });
} catch (err) {
    process.exit(0);
}
```

- [ ] **Step 3: Commit**

```bash
git add vigil-npm/
git commit -m "feat: add npm package wrapper for Vigil CLI"
```

---

### Task 17: Integration Test

**Files:**
- Test: `vigil-core/src/test/java/com/vigil/VigilIntegrationTest.java`

- [ ] **Step 1: Write integration test**

```java
package com.vigil;

import com.vigil.report.*;
import com.vigil.rules.*;
import com.vigil.rules.secrets.HardcodedPasswordRule;
import com.vigil.rules.secrets.HardcodedApiKeyRule;
import com.vigil.rules.encryption.WeakHashAlgorithmRule;
import com.vigil.rules.encryption.WeakCipherRule;
import com.vigil.rules.accesscontrol.UnauthenticatedEndpointRule;
import com.vigil.rules.pii.PiiInLogsRule;
import com.vigil.scanner.Scanner;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import static org.assertj.core.api.Assertions.assertThat;

class VigilIntegrationTest {
    @TempDir Path tempDir;

    @Test
    void shouldScanProjectWithMultipleViolationTypes() throws IOException {
        Files.createDirectories(tempDir.resolve("src/main/java/com/example"));
        Files.writeString(tempDir.resolve("src/main/java/com/example/Config.java"),
            "package com.example; public class Config { private String password = \"admin123\"; private String apiKey = \"sk-live-abc123\"; }");
        Files.writeString(tempDir.resolve("src/main/java/com/example/CryptoUtil.java"),
            "package com.example; import java.security.MessageDigest; import javax.crypto.Cipher; public class CryptoUtil { void h() throws Exception { MessageDigest.getInstance(\"MD5\"); } void e() throws Exception { Cipher.getInstance(\"DES/ECB/PKCS5Padding\"); } }");
        Files.writeString(tempDir.resolve("src/main/java/com/example/UserController.java"),
            "package com.example; import org.springframework.web.bind.annotation.*; @RestController public class UserController { private org.slf4j.Logger logger; @GetMapping(\"/users\") public String g() { return \"u\"; } void p(String email) { logger.info(\"P: \" + email); } }");

        RuleRegistry registry = new RuleRegistry();
        registry.register(new HardcodedPasswordRule()); registry.register(new HardcodedApiKeyRule());
        registry.register(new WeakHashAlgorithmRule()); registry.register(new WeakCipherRule());
        registry.register(new UnauthenticatedEndpointRule()); registry.register(new PiiInLogsRule());

        var violations = new Scanner(registry).scan(tempDir);
        assertThat(violations).hasSizeGreaterThanOrEqualTo(5);

        ReportData data = new ReportData("test-app", LocalDateTime.now(), 3, violations);
        Path report = new HtmlReportGenerator().generate(data, tempDir.resolve("target/vigil"));
        assertThat(report).exists();
        String html = Files.readString(report);
        assertThat(html).contains("VIGIL-SEC-001").contains("VIGIL-ENC-001").contains("pf-v6");
    }

    @Test
    void shouldProduceCleanReportForCompliantProject() throws IOException {
        Files.writeString(tempDir.resolve("App.java"), "public class App { private String name = \"MyApp\"; public static void main(String[] args) {} }");
        ReportData data = new Vigil().scan(tempDir);
        long codeViolations = data.getViolations().stream().filter(v -> v.category() != RuleCategory.DEPENDENCIES).count();
        assertThat(codeViolations).isEqualTo(0);
    }
}
```

- [ ] **Step 2: Run integration test**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -pl vigil-core -Dtest=VigilIntegrationTest -q`

Expected: Tests run: 2, Failures: 0

- [ ] **Step 3: Run full test suite**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn test -q`

Expected: All tests pass across all modules

- [ ] **Step 4: Commit**

```bash
git add vigil-core/src/test/
git commit -m "feat: add end-to-end integration tests for Vigil scanning pipeline"
```

---

### Task 18: Build Verification and Packaging

- [ ] **Step 1: Full build with packaging**

Run: `cd /Users/sshamsud/Projects/Code/vigil && mvn clean package -q`

Expected: BUILD SUCCESS, all modules compile, tests pass, JARs produced

- [ ] **Step 2: Verify CLI JAR works standalone**

Run: `java -jar vigil-cli/target/vigil-cli-1.0.0-SNAPSHOT.jar --help`

Expected: Prints Vigil help text

- [ ] **Step 3: Dog-food — scan the Vigil project itself**

Run: `java -jar vigil-cli/target/vigil-cli-1.0.0-SNAPSHOT.jar . -o target/vigil-self-scan`

Expected: Produces `target/vigil-self-scan/vigil-report.html`

- [ ] **Step 4: Commit any fixes from dog-fooding**

```bash
git add -A
git commit -m "fix: resolve issues found during self-scan"
```
