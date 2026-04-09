package com.vigil.report;

import com.samskivert.mustache.Mustache;
import com.samskivert.mustache.Template;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

public class HtmlReportGenerator implements ReportGenerator {
    private static final DateTimeFormatter DATE_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Override
    public Path generate(ReportData data, Path outputDir) throws IOException {
        Files.createDirectories(outputDir);

        // Load template
        Template template;
        try (Reader reader = new InputStreamReader(
                getClass().getResourceAsStream("/templates/report.mustache"))) {
            template = Mustache.compiler().compile(reader);
        }

        // Build context
        Map<String, Object> context = buildContext(data);

        // Render and write
        String html = template.execute(context);
        Path reportPath = outputDir.resolve("vigil-report.html");
        Files.writeString(reportPath, html);

        return reportPath;
    }

    private Map<String, Object> buildContext(ReportData data) {
        Map<String, Object> context = new HashMap<>();

        context.put("projectName", data.getProjectName());
        context.put("scanTime", data.getScanTime().format(DATE_FORMATTER));
        context.put("filesScanned", data.getFilesScanned());
        context.put("totalViolations", data.getTotalViolations());

        // Severity counts
        context.put("criticalCount", data.getViolationCountBySeverity(Severity.CRITICAL));
        context.put("highCount", data.getViolationCountBySeverity(Severity.HIGH));
        context.put("mediumCount", data.getViolationCountBySeverity(Severity.MEDIUM));
        context.put("lowCount", data.getViolationCountBySeverity(Severity.LOW));

        // Frameworks
        List<Map<String, String>> frameworks = data.getAffectedFrameworks().stream()
            .map(f -> Map.of("name", f.getDisplayName()))
            .collect(Collectors.toList());
        context.put("frameworks", frameworks);
        context.put("hasFrameworks", !frameworks.isEmpty());

        // Violations grouped by file
        List<Map<String, Object>> fileGroups = data.getViolationsByFile().entrySet().stream()
            .map(entry -> {
                Map<String, Object> fileGroup = new HashMap<>();
                fileGroup.put("filePath", entry.getKey());
                fileGroup.put("violationCount", entry.getValue().size());

                List<Map<String, Object>> violations = entry.getValue().stream()
                    .map(this::violationToMap)
                    .collect(Collectors.toList());
                fileGroup.put("violations", violations);

                return fileGroup;
            })
            .sorted((a, b) -> ((String) a.get("filePath")).compareTo((String) b.get("filePath")))
            .collect(Collectors.toList());

        context.put("fileGroups", fileGroups);
        context.put("hasViolations", !fileGroups.isEmpty());
        context.put("noViolations", fileGroups.isEmpty());

        return context;
    }

    private Map<String, Object> violationToMap(Violation v) {
        Map<String, Object> map = new HashMap<>();
        map.put("ruleId", v.ruleId());
        map.put("ruleName", v.ruleName());
        map.put("severity", v.severity().name());
        map.put("severityLower", v.severity().name().toLowerCase());
        map.put("category", v.category().getDisplayName());
        map.put("lineNumber", v.lineNumber());
        map.put("description", v.description());
        map.put("recommendation", v.recommendation());
        map.put("codeSnippet", v.codeSnippet());

        List<Map<String, String>> frameworks = v.frameworks().stream()
            .map(f -> Map.of("name", f.getDisplayName()))
            .collect(Collectors.toList());
        map.put("frameworks", frameworks);

        return map;
    }
}
