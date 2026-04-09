# Vigil - Claude Code Guide

## Project Overview

Vigil is a compliance static analysis tool that scans Java and JS/TS codebases for regulatory compliance violations (SOC2, GDPR, HIPAA, PCI DSS, etc.) and produces a PatternFly 6 HTML report. It ships as a Maven plugin, npm package, and standalone CLI.

## Repository Structure

```
vigil/
├── vigil-core/          # Core engine: scanning, rules, report generation
├── vigil-cli/           # Picocli CLI (builds fat JAR via maven-shade-plugin)
├── vigil-maven-plugin/  # Maven Mojo binding to verify phase
├── vigil-npm/           # npm wrapper that shells out to CLI JAR
└── docs/superpowers/    # Design specs and implementation plans
```

## Build & Test Commands

```bash
# Full build with tests
mvn clean verify

# Run only vigil-core tests (fastest feedback loop)
mvn test -pl vigil-core

# Build CLI fat JAR
mvn clean package -pl vigil-cli -am

# Run CLI against a project
java -jar vigil-cli/target/vigil-cli-1.0.0-SNAPSHOT.jar /path/to/project -o output/

# Run a specific test class
mvn test -pl vigil-core -Dtest=HardcodedSecretsRuleTest
```

## Architecture

- **Scanner Engine** (`com.vigil.scanner`) — FileDiscovery walks directories, Scanner orchestrates parallel scanning, JavaAstScanner parses Java via JavaParser
- **Rules** (`com.vigil.rules`) — 15 rules across 7 categories, all implement `Rule` interface with `check(CompilationUnit, filePath)` method
- **Dependencies** (`com.vigil.dependencies`) — MavenPomParser/NpmPackageParser extract deps, OsvClient queries CVE database
- **Report** (`com.vigil.report`) — HtmlReportGenerator uses JMustache with PatternFly 6 template at `src/main/resources/templates/report.mustache`
- **Vigil** (`com.vigil.Vigil`) — public facade that wires everything together

## Key Conventions

- **Java 17** — records, text blocks, pattern matching, sealed classes are all fine
- **groupId** is `io.github.yamalameyooooo` (Maven coordinate), but Java packages use `com.vigil.*`
- **Rules never throw** — they return empty lists on errors, never break the scan
- **Vigil never fails builds** — always exits 0, report-only mode
- **Tests use JUnit 5 + AssertJ** — `@TempDir` for file system tests, JavaParser for rule tests
- **No cross-file analysis** — each file is scanned independently

## Adding a New Rule

1. Create a class in the appropriate package under `vigil-core/src/main/java/com/vigil/rules/<category>/`
2. Implement `Rule` interface: `getId()`, `getName()`, `getCategory()`, `check(CompilationUnit, String)`
3. Register it in `Vigil.createDefaultRegistry()`
4. Add tests in `vigil-core/src/test/java/com/vigil/rules/<category>/`
5. Rule ID convention: `VIGIL-<CAT>-<NNN>` (e.g., `VIGIL-SEC-004`)

## Publishing

- Maven Central via Sonatype OSSRH (nexus-staging-maven-plugin)
- npm via npmjs.com
- Automated via GitHub Actions on `v*` tag push
- Requires secrets: `OSSRH_USERNAME`, `OSSRH_TOKEN`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`, `NPM_TOKEN`

## Common Patterns in Rules

```java
// Find method calls: MessageDigest.getInstance("MD5")
cu.findAll(MethodCallExpr.class).forEach(call -> {
    if (call.getNameAsString().equals("getInstance")
            && call.getScope().isPresent()
            && call.getScope().get().toString().equals("MessageDigest")) {
        // check arguments, create Violation
    }
});

// Find variable declarations with string literal values
cu.findAll(VariableDeclarator.class).forEach(v -> {
    if (v.getInitializer().isPresent() && v.getInitializer().get().isStringLiteralExpr()) {
        // check variable name, create Violation
    }
});

// Get line number
node.getBegin().map(p -> p.line).orElse(0)
```

## PII Detection

`PiiFieldDetector` is a shared utility used by PII, logging, and storage rules. It checks variable/field names against regex patterns for PII terms (email, ssn, phone, etc.) and returns appropriate severity (CRITICAL for SSN/health data, HIGH for name/email).
