package com.vigil.dependencies;

import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class DependencyAnalyzer {
    private final MavenPomParser mavenParser = new MavenPomParser();
    private final NpmPackageParser npmParser = new NpmPackageParser();
    private final OsvClient osvClient = new OsvClient();

    private static final Set<Framework> DEPENDENCY_FRAMEWORKS = Set.of(
        Framework.SOC2,
        Framework.PCI_DSS,
        Framework.ISO_27001
    );

    public List<Violation> analyze(List<Path> manifests) {
        List<Violation> violations = new ArrayList<>();

        for (Path manifest : manifests) {
            String fileName = manifest.getFileName().toString();

            List<DependencyInfo> dependencies;
            if (fileName.equals("pom.xml")) {
                dependencies = mavenParser.parse(manifest);
            } else if (fileName.equals("package.json")) {
                dependencies = npmParser.parse(manifest);
            } else {
                continue;
            }

            for (DependencyInfo dependency : dependencies) {
                List<VulnerabilityInfo> vulnerabilities = osvClient.queryVulnerabilities(dependency);

                for (VulnerabilityInfo vuln : vulnerabilities) {
                    Severity severity = parseSeverity(vuln.severity());

                    String description = String.format(
                        "Vulnerable dependency detected: %s:%s@%s - %s (%s)",
                        dependency.groupId(),
                        dependency.artifactId(),
                        dependency.version(),
                        vuln.id(),
                        vuln.summary()
                    );

                    String recommendation = String.format(
                        "Update %s to a patched version that resolves %s",
                        dependency.artifactId(),
                        vuln.id()
                    );

                    violations.add(new Violation(
                        "VIGIL-DEP-001",
                        "Vulnerable Dependency",
                        RuleCategory.DEPENDENCIES,
                        severity,
                        manifest.toString(),
                        1,
                        String.format("%s:%s:%s", dependency.groupId(), dependency.artifactId(), dependency.version()),
                        DEPENDENCY_FRAMEWORKS,
                        description,
                        recommendation
                    ));
                }
            }
        }

        return violations;
    }

    private Severity parseSeverity(String severityString) {
        return switch (severityString.toUpperCase()) {
            case "CRITICAL" -> Severity.CRITICAL;
            case "HIGH" -> Severity.HIGH;
            case "LOW" -> Severity.LOW;
            default -> Severity.MEDIUM;
        };
    }
}
