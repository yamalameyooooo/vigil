package com.vigil.report;

import com.vigil.rules.Framework;
import com.vigil.rules.Severity;

import java.io.PrintStream;
import java.nio.file.Path;

public class ConsoleSummaryPrinter {
    private final PrintStream out;

    public ConsoleSummaryPrinter(PrintStream out) {
        this.out = out;
    }

    public ConsoleSummaryPrinter() {
        this(System.out);
    }

    public void print(ReportData data, Path reportPath) {
        out.println();
        out.println("=".repeat(70));
        out.println("VIGIL COMPLIANCE SCAN SUMMARY");
        out.println("=".repeat(70));
        out.println();

        out.printf("Project:        %s%n", data.getProjectName());
        out.printf("Files Scanned:  %d%n", data.getFilesScanned());
        out.printf("Scan Time:      %s%n", data.getScanTime());
        out.println();

        out.println("Violations by Severity:");
        out.printf("  CRITICAL: %d%n", data.getViolationCountBySeverity(Severity.CRITICAL));
        out.printf("  HIGH:     %d%n", data.getViolationCountBySeverity(Severity.HIGH));
        out.printf("  MEDIUM:   %d%n", data.getViolationCountBySeverity(Severity.MEDIUM));
        out.printf("  LOW:      %d%n", data.getViolationCountBySeverity(Severity.LOW));
        out.printf("  TOTAL:    %d%n", data.getTotalViolations());
        out.println();

        if (!data.getAffectedFrameworks().isEmpty()) {
            out.println("Affected Compliance Frameworks:");
            for (Framework framework : data.getAffectedFrameworks()) {
                out.printf("  - %s%n", framework.getDisplayName());
            }
            out.println();
        }

        if (reportPath != null) {
            out.printf("Report generated: %s%n", reportPath.toAbsolutePath());
        }

        out.println("=".repeat(70));
        out.println();
    }
}
