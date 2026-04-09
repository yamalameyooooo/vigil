package com.vigil.rules.logging;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import com.vigil.rules.Rule;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class MissingAuditLogRule implements Rule {

    private static final String RULE_ID = "VIGIL-LOG-002";
    private static final String RULE_NAME = "Missing Audit Log";
    private static final Pattern AUDIT_METHOD_PATTERN = Pattern.compile(
        ".*(login|logout|authenticate|authorize|change[_-]?password|reset[_-]?password|" +
        "grant[_-]?role|revoke[_-]?role|delete[_-]?user|update[_-]?permission).*",
        Pattern.CASE_INSENSITIVE
    );
    private static final Set<String> LOG_METHODS = Set.of(
        "info", "debug", "warn", "error", "trace", "log", "println", "print"
    );

    @Override
    public String getId() {
        return RULE_ID;
    }

    @Override
    public String getName() {
        return RULE_NAME;
    }

    @Override
    public RuleCategory getCategory() {
        return RuleCategory.LOGGING;
    }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            String methodName = method.getNameAsString();

            // Check if it's a security-sensitive method
            if (AUDIT_METHOD_PATTERN.matcher(methodName).matches()) {
                // Check if method contains any logging calls
                boolean hasLogging = method.findAll(MethodCallExpr.class).stream()
                    .anyMatch(call -> LOG_METHODS.contains(call.getNameAsString()));

                if (!hasLogging) {
                    int lineNumber = method.getBegin().map(p -> p.line).orElse(0);
                    String codeSnippet = method.getDeclarationAsString();

                    violations.add(new Violation(
                        RULE_ID,
                        RULE_NAME,
                        RuleCategory.LOGGING,
                        Severity.MEDIUM,
                        filePath,
                        lineNumber,
                        codeSnippet,
                        Set.of(Framework.SOC2, Framework.HIPAA, Framework.PCI_DSS, Framework.GDPR),
                        "Security-sensitive method lacks audit logging: " + methodName,
                        "Add audit logging for authentication, authorization, and privileged operations"
                    ));
                }
            }
        });

        return violations;
    }
}
