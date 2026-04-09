package com.vigil.rules;

import java.util.Set;

public record Violation(
    String ruleId,
    String ruleName,
    RuleCategory category,
    Severity severity,
    String filePath,
    int lineNumber,
    String codeSnippet,
    Set<Framework> frameworks,
    String description,
    String recommendation
) {}
