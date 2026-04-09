# Vigil

Compliance static analysis tool for Java and JavaScript/TypeScript codebases. Vigil scans your source code and dependencies for violations across major regulatory frameworks and produces a detailed HTML report.

## What It Detects

| Category | Examples | Rule IDs |
|----------|----------|----------|
| **Hardcoded Secrets** | Passwords, API keys, tokens in source code | VIGIL-SEC-001 to 003 |
| **Weak Encryption** | MD5, SHA1, DES, RC4, ECB mode, TLS 1.0/1.1 | VIGIL-ENC-001 to 003 |
| **PII Handling** | PII in logs, cookies, unmasked API responses | VIGIL-PII-001 to 003 |
| **Logging Compliance** | Sensitive data in logs, missing audit trails | VIGIL-LOG-001 to 002 |
| **Data Storage** | Insecure cookies, unencrypted PII file writes | VIGIL-STO-001 to 002 |
| **Access Control** | Unauthenticated REST endpoints | VIGIL-AC-001 to 002 |
| **Insecure Dependencies** | Known CVEs via OSV database lookup | VIGIL-DEP-001 |

## Compliance Frameworks

Every finding is tagged with the frameworks it violates:

SOC 2 | GDPR | HIPAA | PCI DSS | ISO 27001 | CCPA | LGPD | POPIA | PIPEDA | PDPA

## Quick Start

### Maven Plugin

Add to your project's `pom.xml`:

```xml
<plugin>
    <groupId>io.github.yamalameyooooo</groupId>
    <artifactId>vigil-maven-plugin</artifactId>
    <version>1.0.0</version>
    <executions>
        <execution>
            <goals><goal>scan</goal></goals>
            <phase>verify</phase>
        </execution>
    </executions>
</plugin>
```

Run `mvn verify` — report appears at `target/vigil/vigil-report.html`.

### npm Package

```bash
npm install --save-dev vigil-scan
```

Add to `package.json`:

```json
{
  "scripts": {
    "vigil": "vigil .",
    "postbuild": "vigil ."
  }
}
```

Run `npm run vigil` — report appears at `vigil-report/vigil-report.html`.

**Prerequisite:** Java 17+ must be installed.

### Standalone CLI

```bash
java -jar vigil-cli.jar /path/to/project -o /path/to/output
```

## How It Works

1. **File Discovery** — walks your project, finds `.java`, `.js`, `.ts`, `.tsx` files (skips `node_modules`, `target`, etc.)
2. **AST Parsing** — parses source files into Abstract Syntax Trees using JavaParser (Java) and tree-sitter (JS/TS)
3. **Rule Execution** — 15 hardcoded rules analyze AST nodes for compliance violations
4. **Dependency Analysis** — parses `pom.xml` / `package.json`, queries the OSV API for known CVEs
5. **Report Generation** — produces a self-contained HTML report with PatternFly 6 UI

## Report

The HTML report includes:

- Summary dashboard with severity counts
- Findings grouped by file with collapsible sections
- Code snippets showing the violation
- Framework badges per violation
- Fix recommendations
- Client-side filtering by severity, category, and search
- Empty state when no violations found

Vigil **never fails your build** — it only generates a report.

## Project Structure

```
vigil/
├── vigil-core/          # Core scanning engine, rules, report generator
├── vigil-cli/           # Picocli command-line interface
├── vigil-maven-plugin/  # Maven plugin (binds to verify phase)
└── vigil-npm/           # npm package wrapper
```

## Building From Source

```bash
git clone https://github.com/yamalameyooooo/vigil.git
cd vigil
mvn clean package
```

The CLI fat JAR will be at `vigil-cli/target/vigil-cli-1.0.0-SNAPSHOT.jar`.

## Tech Stack

- Java 17
- JavaParser — AST parsing for Java
- Picocli — CLI framework
- JMustache — HTML report templating
- PatternFly 6 — report UI design system
- Jackson — JSON parsing for package.json and OSV API
- OSV API — CVE vulnerability lookups
- JUnit 5 + AssertJ — testing

## License

[Apache License 2.0](LICENSE)
