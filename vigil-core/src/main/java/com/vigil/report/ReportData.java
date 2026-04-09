package com.vigil.report;

import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class ReportData {
    private final String projectName;
    private final LocalDateTime scanTime;
    private final int filesScanned;
    private final List<Violation> violations;

    public ReportData(String projectName, LocalDateTime scanTime, int filesScanned, List<Violation> violations) {
        this.projectName = projectName;
        this.scanTime = scanTime;
        this.filesScanned = filesScanned;
        this.violations = violations;
    }

    public String getProjectName() {
        return projectName;
    }

    public LocalDateTime getScanTime() {
        return scanTime;
    }

    public int getFilesScanned() {
        return filesScanned;
    }

    public List<Violation> getViolations() {
        return violations;
    }

    public int getTotalViolations() {
        return violations.size();
    }

    public Map<Severity, List<Violation>> getViolationsBySeverity() {
        return violations.stream()
            .collect(Collectors.groupingBy(Violation::severity));
    }

    public Map<RuleCategory, List<Violation>> getViolationsByCategory() {
        return violations.stream()
            .collect(Collectors.groupingBy(Violation::category));
    }

    public Map<String, List<Violation>> getViolationsByFile() {
        return violations.stream()
            .collect(Collectors.groupingBy(Violation::filePath));
    }

    public Set<Framework> getAffectedFrameworks() {
        return violations.stream()
            .flatMap(v -> v.frameworks().stream())
            .collect(Collectors.toSet());
    }

    public long getViolationCountBySeverity(Severity severity) {
        return violations.stream()
            .filter(v -> v.severity() == severity)
            .count();
    }
}
