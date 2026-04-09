# Vigil Publishing Setup Design

## Overview

Configure Vigil for public distribution on Maven Central and npmjs.com, with automated publishing via GitHub Actions on git tag push.

## Core Decisions

| Decision | Choice |
|----------|--------|
| Maven groupId | `io.github.yamalameyooooo` |
| npm package name | `vigil-scan` |
| License | Apache 2.0 |
| Publishing trigger | GitHub Actions on `v*` tag push |

## Changes Required

### 1. Parent POM Updates

- Change `groupId` from `com.vigil` to `io.github.yamalameyooooo`
- Add `<url>`, `<licenses>`, `<developers>`, `<scm>` metadata
- Add `<distributionManagement>` pointing to Sonatype OSSRH
- Add `release` profile with: `maven-source-plugin`, `maven-javadoc-plugin`, `maven-gpg-plugin`, `nexus-staging-maven-plugin`
- Java package names (`com.vigil.*`) stay unchanged

### 2. Module POM Updates

All child POMs update `<parent><groupId>` to `io.github.yamalameyooooo`.

### 3. npm Package Updates

Add `repository`, `bugs`, `homepage`, `license`, `author`, `publishConfig` to `vigil-npm/package.json`.

### 4. GitHub Actions Workflows

- **`ci.yml`** — on push/PR: build + test
- **`release.yml`** — on `v*` tag: build, sign, deploy to Maven Central + npm

### 5. LICENSE File

Apache 2.0 at project root.

### 6. GitHub Secrets Required

`OSSRH_USERNAME`, `OSSRH_TOKEN`, `GPG_PRIVATE_KEY`, `GPG_PASSPHRASE`, `NPM_TOKEN`

### 7. Consumer Usage After Publishing

**Maven:**
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

**npm:**
```json
{
  "devDependencies": { "vigil-scan": "^1.0.0" },
  "scripts": { "vigil": "vigil .", "postbuild": "vigil ." }
}
```
