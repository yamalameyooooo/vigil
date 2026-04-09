# Vigil — Compliance Static Analysis Tool

## Overview

Vigil is a build-phase compliance static analysis tool that scans Java and JavaScript/TypeScript codebases for compliance violations across major regulatory frameworks (SOC2, GDPR, HIPAA, PCI DSS, ISO 27001, CCPA, LGPD, POPIA, and more). It analyzes source code via AST parsing and dependencies via CVE database lookups, then produces a production-grade HTML report using PatternFly 6.

Vigil ships as a **Maven plugin** (native) and an **npm package** (CLI wrapper), allowing teams in either ecosystem to integrate compliance scanning into their build pipeline.

## Core Design Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Scanning approach | Pure AST-based | Fewer false positives, understands code structure and context |
| Core language | Java | Native Maven plugin, CLI wraps for npm |
| Rule definitions | Hardcoded in Java | Simple, rules ship with the tool, new rules via version updates |
| Framework selection | Scan everything, tag findings | No config needed, developer sees full compliance picture |
| Build behavior | Report only | No build failure, generates HTML report, prints console summary |
| Report format | Self-contained HTML with PatternFly 6 | Production-grade UI, works offline, single file |

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   Vigil Core                     │
│                                                  │
│  ┌───────────┐  ┌───────────┐  ┌──────────────┐ │
│  │  Scanner   │  │   Rule    │  │   Report     │ │
│  │  Engine    │  │  Engine   │  │  Generator   │ │
│  └─────┬─────┘  └─────┬─────┘  └──────┬───────┘ │
│        │              │               │          │
│  ┌─────┴─────┐  ┌─────┴─────┐        │          │
│  │ Java AST  │  │ Rules     │        │          │
│  │ Parser    │  │ (per      │        │          │
│  │(JavaParser)│  │ category) │        │          │
│  ├───────────┤  └───────────┘        │          │
│  │ JS/TS AST │                       │          │
│  │ Parser    │                       │          │
│  │(tree-sitter)│                     │          │
│  └───────────┘                       │          │
├─────────────────────────────────────────────────┤
│              Dependency Analyzer                 │
│         (Maven POM / package.json parser         │
│          + CVE database lookup via OSV API)       │
└─────────────────────────────────────────────────┘
         │                          │
    ┌────┴────┐               ┌────┴────┐
    │  Maven  │               │   npm   │
    │ Plugin  │               │ Package │
    │ (native)│               │(CLI wrap)│
    └─────────┘               └─────────┘
```

### Components

1. **Scanner Engine** — Orchestrates scanning. Takes a project directory, identifies file types, dispatches to the correct AST parser. Runs file parsing and rule execution in parallel using Java's `ForkJoinPool`.

2. **AST Parsers**
   - **JavaParser** (Java library) for `.java` files
   - **tree-sitter** (Java bindings) for `.js`, `.ts`, `.tsx` files
   - Both produce ASTs that the Rule Engine can walk

3. **Rule Engine** — Takes an AST, runs all applicable rules against it, collects violations. Each rule is a Java class implementing the `Rule` interface with a `visit` method.

4. **Dependency Analyzer** — Parses `pom.xml` / `package.json` and lock files. Resolves dependency versions. Queries the OSV (Open Source Vulnerabilities) API for known CVEs. No local database required.

5. **Report Generator** — Takes all violations, feeds them into a PatternFly 6 HTML template (via Mustache), produces a single self-contained HTML report file.

6. **Maven Plugin** — Native Maven Mojo. Binds to the `verify` phase. Configuration in the consuming project's `pom.xml`.

7. **npm Package** — Bundles the Vigil CLI fat JAR. Small JS wrapper launches `java -jar vigil-cli.jar`. Requires JVM on the machine (documented prerequisite).

## Project Structure

```
vigil/
├── pom.xml                              (parent POM, multi-module Maven project)
│
├── vigil-core/                          (core scanning engine)
│   ├── pom.xml
│   └── src/main/java/com/vigil/
│       ├── Vigil.java                   (main entry point / facade)
│       ├── scanner/
│       │   ├── Scanner.java             (orchestrator)
│       │   ├── FileDiscovery.java       (finds source files by type)
│       │   ├── java/
│       │   │   └── JavaAstParser.java   (JavaParser-based)
│       │   └── js/
│       │       └── JsAstParser.java     (tree-sitter-based)
│       ├── rules/
│       │   ├── Rule.java                (interface)
│       │   ├── RuleRegistry.java        (collects and provides all rules)
│       │   ├── Violation.java           (data class for a single finding)
│       │   ├── Severity.java            (enum: CRITICAL, HIGH, MEDIUM, LOW)
│       │   ├── Framework.java           (enum: SOC2, GDPR, HIPAA, PCI_DSS, etc.)
│       │   ├── RuleCategory.java        (enum: SECRETS, PII, DEPENDENCIES, etc.)
│       │   ├── secrets/
│       │   │   ├── HardcodedPasswordRule.java
│       │   │   ├── HardcodedApiKeyRule.java
│       │   │   └── HardcodedTokenRule.java
│       │   ├── pii/
│       │   │   ├── PiiInLogsRule.java
│       │   │   ├── PiiInCookiesRule.java
│       │   │   └── UnmaskedPiiResponseRule.java
│       │   ├── dependencies/
│       │   │   └── KnownCveRule.java
│       │   ├── storage/
│       │   │   ├── UnencryptedFileWriteRule.java
│       │   │   └── InsecureCookieRule.java
│       │   ├── logging/
│       │   │   ├── SensitiveDataInLogsRule.java
│       │   │   └── MissingAuditLogRule.java
│       │   ├── encryption/
│       │   │   ├── WeakHashAlgorithmRule.java
│       │   │   ├── WeakCipherRule.java
│       │   │   └── WeakTlsRule.java
│       │   └── accesscontrol/
│       │       ├── UnauthenticatedEndpointRule.java
│       │       └── MissingAuthMiddlewareRule.java
│       ├── dependencies/
│       │   ├── DependencyAnalyzer.java
│       │   ├── MavenPomParser.java
│       │   └── NpmPackageParser.java
│       └── report/
│           ├── ReportGenerator.java
│           ├── HtmlReportGenerator.java
│           └── templates/
│               └── report.html          (Mustache template with PF6)
│
├── vigil-cli/                           (standalone CLI)
│   ├── pom.xml
│   └── src/main/java/com/vigil/cli/
│       └── VigilCli.java                (Picocli-based CLI entry point)
│
├── vigil-maven-plugin/                  (Maven plugin wrapper)
│   ├── pom.xml
│   └── src/main/java/com/vigil/maven/
│       └── VigilMojo.java               (binds to verify phase)
│
└── vigil-npm/                           (npm package wrapper)
    ├── package.json
    ├── bin/
    │   └── vigil.js                     (launches the CLI JAR)
    └── lib/
        └── vigil-cli.jar                (fat JAR bundled at publish time)
```

## Rule Categories

### 1. Hardcoded Secrets Detection

- **What it detects:** API keys, passwords, tokens, private keys assigned as string literals
- **AST approach:** Visit variable declarations and assignments. Check if the variable name suggests a secret (`password`, `apiKey`, `token`, `secret`, `credential`, `privateKey`, etc.) and the value is a string literal. Also catches secrets in annotations (e.g., `@Value("hardcoded-password")`), constructor arguments, and method call arguments.
- **Severity:** CRITICAL
- **Frameworks:** SOC2, GDPR, HIPAA, PCI DSS, ISO 27001

### 2. PII Handling Violations

- **What it detects:** PII fields (email, SSN, phone, address, dateOfBirth, firstName, lastName) being passed to loggers, written to files without encryption, stored in cookies, or returned in API responses without masking
- **AST approach:** Track variables/fields whose names suggest PII. Check if those references appear as arguments to logging calls (`logger.info()`, `console.log()`), file I/O methods, or unmasked response builders.
- **Severity:** HIGH to CRITICAL (depends on PII type — SSN/health data is CRITICAL, name/email is HIGH)
- **Frameworks:** GDPR, HIPAA, CCPA, LGPD, POPIA

### 3. Insecure Dependencies

- **What it detects:** Dependencies with known CVEs
- **Approach:** Parse `pom.xml` / `package.json` / lock files. Resolve dependency versions. Query the OSV (Open Source Vulnerabilities) database API for known vulnerabilities.
- **Severity:** Mapped from CVE severity (CVSS score)
- **Frameworks:** SOC2, PCI DSS, ISO 27001

### 4. Data Storage Patterns

- **What it detects:** Unencrypted file writes involving sensitive data, insecure cookie settings (missing `Secure`/`HttpOnly`/`SameSite` flags), database queries with plaintext sensitive data
- **AST approach:** Visit method calls for file I/O APIs (`FileWriter`, `BufferedWriter`, `fs.writeFile`, `fs.appendFile`) where arguments include PII-typed variables without encryption wrappers. Visit cookie creation calls (`new Cookie()`, `res.cookie()`) and check for missing security flags.
- **Severity:** HIGH
- **Frameworks:** GDPR, HIPAA, PCI DSS, SOC2

### 5. Logging Compliance

- **What it detects:** Sensitive data in log statements, missing audit logging for security-critical operations (login, logout, permission changes, data access)
- **AST approach:** Visit all logging method calls (`logger.info/warn/error/debug`, `console.log/warn/error`, `LOG.info`, etc.). Check if arguments include PII-typed variables or sensitive field references. For missing audit logging: flag authentication/authorization methods that lack any logging calls.
- **Severity:** HIGH (sensitive data in logs), MEDIUM (missing audit logs)
- **Frameworks:** SOC2, HIPAA, PCI DSS, GDPR

### 6. Encryption Standards

- **What it detects:** Weak hash algorithms (MD5, SHA1), weak ciphers (DES, RC4, Blowfish), weak TLS versions (TLS 1.0, 1.1, SSL), hardcoded initialization vectors, ECB mode usage
- **AST approach:** Visit method calls to crypto APIs (`MessageDigest.getInstance()`, `Cipher.getInstance()`, `SecretKeySpec()`, `crypto.createHash()`, `crypto.createCipheriv()`). Check the algorithm/mode argument string for weak values.
- **Severity:** CRITICAL (weak ciphers/TLS), HIGH (weak hashes, ECB mode)
- **Frameworks:** PCI DSS, HIPAA, SOC2, ISO 27001

### 7. Access Control Patterns

- **What it detects:** REST endpoints/controllers missing authentication or authorization checks
- **AST approach:**
  - **Java:** Visit classes annotated with `@RestController` / `@Controller`. Check if handler methods have `@PreAuthorize`, `@Secured`, `@RolesAllowed`, or if a `SecurityFilterChain` / `WebSecurityConfigurerAdapter` covers the path.
  - **JS/TS:** Check Express route definitions (`app.get()`, `router.post()`) for authentication middleware in the handler chain. Check for missing auth middleware in route groups.
- **Severity:** HIGH
- **Frameworks:** SOC2, PCI DSS, HIPAA, ISO 27001

## Violation Data Model

Each violation carries:

```java
public class Violation {
    String ruleId;           // e.g., "VIGIL-SEC-001"
    String ruleName;         // e.g., "Hardcoded Password"
    RuleCategory category;   // e.g., SECRETS
    Severity severity;       // CRITICAL, HIGH, MEDIUM, LOW
    String filePath;         // relative path to the scanned file
    int lineNumber;          // line where the violation was found
    String codeSnippet;      // the offending line(s) of code
    Set<Framework> frameworks; // which compliance frameworks are violated
    String description;      // human-readable explanation
    String recommendation;   // actionable fix guidance
}
```

## Execution Pipeline

```
Developer's Project
        │
        ▼
┌──────────────────┐
│  1. File Discovery│  Walk project dir, collect .java, .js, .ts, .tsx,
│                    │  pom.xml, package.json, lock files
└────────┬─────────┘
         ▼
┌──────────────────┐
│  2. Parse Phase   │  Java files → JavaParser ASTs
│                    │  JS/TS files → tree-sitter ASTs
│                    │  pom.xml → Maven dependency list
│                    │  package.json → npm dependency list
└────────┬─────────┘
         ▼
┌──────────────────┐
│  3. Rule Execution│  Each AST passed through all applicable rules
│                    │  Each dependency list → KnownCveRule
│                    │  Rules emit Violation objects
└────────┬─────────┘
         ▼
┌──────────────────┐
│  4. Aggregation   │  Collect all Violations
│                    │  Group by file, category, framework, severity
│                    │  Compute summary statistics
└────────┬─────────┘
         ▼
┌──────────────────┐
│  5. Report Gen    │  Feed aggregated data into PF6 HTML template
│                    │  Write vigil-report.html to output directory
│                    │  Print summary to console
└──────────────────┘
```

### Execution Details

- **Parallelism:** Files are parsed and scanned in parallel using Java's `ForkJoinPool`. Each file is independent — no cross-file analysis in v1.
- **Output location:**
  - Maven: `target/vigil/vigil-report.html`
  - npm: `./vigil-report/vigil-report.html` (project root)
- **Console summary:** A brief summary always prints to stdout:
  ```
  Vigil Compliance Scan Complete
  ─────────────────────────────
  Files scanned:    142
  Violations found: 23
    CRITICAL: 3  |  HIGH: 8  |  MEDIUM: 9  |  LOW: 3
  Frameworks affected: SOC2, GDPR, PCI DSS
  Full report: target/vigil/vigil-report.html
  ```
- **Exit code:** Always `0` (report only, never fails the build).

## HTML Report Design (PatternFly 6)

Single self-contained HTML file with PatternFly 6 CSS inlined. No external dependencies — works offline.

### PatternFly 6 Components Used

| Component | Purpose |
|-----------|---------|
| Page / PageSection | Overall layout structure |
| Card | Summary dashboard cards, violation detail cards |
| Label | Severity badges (Critical=red, High=orange, Medium=gold, Low=blue) |
| Badge | Framework tags on each violation |
| ExpandableSection | Collapsible file groups |
| Toolbar + Filters | Filter bar (severity, category, framework dropdowns) |
| SearchInput | File/rule text search |
| DescriptionList | Violation details (rule ID, line, recommendation) |
| CodeBlock | Offending code snippet display |
| Alert | Fix recommendations |
| EmptyState | Zero-violations congratulatory state |

### Report Layout

```
┌─────────────────────────────────────────────────────┐
│  VIGIL — Compliance Scan Report            [logo]    │
│  Project: my-app  |  Scanned: 2026-04-09 14:32      │
│  Files: 142  |  Violations: 23                       │
├─────────────────────────────────────────────────────┤
│                                                      │
│  ┌─ Summary Dashboard (PF6 Cards) ───────────────┐  │
│  │  ● CRITICAL: 3   ● HIGH: 8                    │  │
│  │  ● MEDIUM: 9     ● LOW: 3                     │  │
│  │                                                │  │
│  │  [Bar chart by category]                       │  │
│  │  Secrets: 4 | PII: 6 | Encryption: 5 | ...    │  │
│  │                                                │  │
│  │  [Framework coverage badges]                   │  │
│  │  SOC2: 12 issues | GDPR: 8 | PCI DSS: 5      │  │
│  └────────────────────────────────────────────────┘  │
│                                                      │
│  ┌─ PF6 Toolbar + Filters ───────────────────────┐  │
│  │  [Severity ▼] [Category ▼] [Framework ▼]      │  │
│  │  [Search by file/rule...]                      │  │
│  └────────────────────────────────────────────────┘  │
│                                                      │
│  ┌─ Findings (PF6 ExpandableSection per file) ───┐  │
│  │                                                │  │
│  │  ▸ src/main/java/UserService.java (4 issues)  │  │
│  │    ┌─ PF6 Card ──────────────────────────┐    │  │
│  │    │ [CRITICAL label]  VIGIL-SEC-001      │    │  │
│  │    │ Hardcoded password at line 42        │    │  │
│  │    │ [SOC2] [GDPR] [PCI DSS] badges      │    │  │
│  │    │                                      │    │  │
│  │    │ PF6 CodeBlock:                       │    │  │
│  │    │ String dbPass = "admin123";          │    │  │
│  │    │                                      │    │  │
│  │    │ PF6 Alert (info):                    │    │  │
│  │    │ Use environment variables or a       │    │  │
│  │    │ secrets manager like Vault/AWS SM    │    │  │
│  │    └──────────────────────────────────────┘    │  │
│  │                                                │  │
│  │  ▸ src/controllers/AuthController.java (2)    │  │
│  │  ▸ src/utils/crypto.ts (3 issues)             │  │
│  └────────────────────────────────────────────────┘  │
│                                                      │
│  ┌─ Dependency Vulnerabilities ──────────────────┐  │
│  │  ▸ log4j-core 2.14.1 — CVE-2021-44228 (CRIT) │  │
│  │  ▸ lodash 4.17.20 — CVE-2021-23337 (HIGH)    │  │
│  └────────────────────────────────────────────────┘  │
│                                                      │
│  Generated by Vigil v1.0.0                           │
└─────────────────────────────────────────────────────┘
```

### Visual Style
- Dark header with Vigil branding
- Clean white content area
- Color-coded severity throughout (PatternFly 6 status colors)
- Responsive layout
- Client-side filtering and search via inline JavaScript
- Production-grade look — designed to feel like a real product dashboard

## Key Libraries

| Library | Version | Purpose |
|---------|---------|---------|
| JavaParser | 3.x | AST parsing for Java source files |
| tree-sitter (Java bindings) | Latest | AST parsing for JS/TS/TSX files |
| Picocli | 4.x | CLI framework for vigil-cli |
| OSV API | HTTP | CVE lookups for dependencies |
| Mustache (JMustache) | Latest | HTML report templating |
| PatternFly 6 | 6.x | Report UI design system (CSS inlined) |
| Maven Plugin API | 3.x | Maven plugin development |

## Integration

### Maven Usage

```xml
<plugin>
    <groupId>com.vigil</groupId>
    <artifactId>vigil-maven-plugin</artifactId>
    <version>1.0.0</version>
    <executions>
        <execution>
            <goals>
                <goal>scan</goal>
            </goals>
            <phase>verify</phase>
        </execution>
    </executions>
</plugin>
```

Run: `mvn verify` — Vigil scans after tests, produces report at `target/vigil/vigil-report.html`.

### npm Usage

```json
{
  "devDependencies": {
    "vigil-scan": "^1.0.0"
  },
  "scripts": {
    "vigil": "vigil scan .",
    "postbuild": "vigil scan ."
  }
}
```

Run: `npm run vigil` or automatically after `npm run build`.

**Prerequisite:** JVM 17+ must be installed on the machine.

## Compliance Frameworks Covered

| Framework | Region | Focus |
|-----------|--------|-------|
| SOC 2 | US | Security, availability, processing integrity |
| GDPR | EU | Data protection, privacy, consent |
| HIPAA | US | Healthcare data protection |
| PCI DSS | Global | Payment card data security |
| ISO 27001 | Global | Information security management |
| CCPA/CPRA | US (California) | Consumer privacy rights |
| LGPD | Brazil | Data protection (GDPR-modeled) |
| POPIA | South Africa | Data protection |
| PIPEDA | Canada | Privacy in the private sector |
| PDPA | Singapore/Thailand | Personal data protection |

## Scope Boundaries (v1)

- **No cross-file analysis** — each file is analyzed independently. Data flow tracking is within a single file only.
- **No custom rules** — rules are hardcoded. Users cannot add their own rules in v1.
- **No CI/CD integrations** — no GitHub Actions, Jenkins plugins, etc. Users integrate via Maven/npm.
- **No suppression mechanism** — no way to mark a finding as false positive or intentionally accepted in v1.
- **No incremental scanning** — full project scan every time.
- **JVM required for npm users** — the npm package does not bundle a JVM.
