package com.vigil.rules.logging;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import com.vigil.rules.Rule;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class SensitiveDataInLogsRule implements Rule {

    private static final String RULE_ID = "VIGIL-LOG-001";
    private static final String RULE_NAME = "Sensitive Data in Logs";
    private static final Set<String> LOG_METHODS = Set.of(
        "info", "debug", "warn", "error", "trace", "log", "println", "print"
    );
    private static final Pattern SENSITIVE_PATTERN = Pattern.compile(
        ".*(password|secret|credential|credit[_-]?card|cvv|pin|private[_-]?key).*",
        Pattern.CASE_INSENSITIVE
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

        cu.findAll(MethodCallExpr.class).forEach(methodCall -> {
            String methodName = methodCall.getNameAsString();

            // Check if it's a logging method
            if (LOG_METHODS.contains(methodName)) {
                // Check arguments for sensitive variable names
                for (Expression arg : methodCall.getArguments()) {
                    checkForSensitiveDataInExpression(arg, methodCall, filePath, violations);
                }
            }
        });

        return violations;
    }

    private void checkForSensitiveDataInExpression(Expression expr, MethodCallExpr methodCall,
                                                    String filePath, List<Violation> violations) {
        if (expr instanceof NameExpr) {
            NameExpr nameExpr = (NameExpr) expr;
            String varName = nameExpr.getNameAsString();

            if (SENSITIVE_PATTERN.matcher(varName).matches()) {
                int lineNumber = methodCall.getBegin().map(p -> p.line).orElse(0);
                String codeSnippet = methodCall.toString();

                violations.add(new Violation(
                    RULE_ID,
                    RULE_NAME,
                    RuleCategory.LOGGING,
                    Severity.HIGH,
                    filePath,
                    lineNumber,
                    codeSnippet,
                    Set.of(Framework.SOC2, Framework.HIPAA, Framework.PCI_DSS, Framework.GDPR),
                    "Sensitive data logged without masking: " + varName,
                    "Never log passwords, secrets, or credentials. Use redaction or masking if logging is necessary"
                ));
            }
        }

        // Recursively check nested expressions
        expr.getChildNodes().forEach(child -> {
            if (child instanceof Expression) {
                checkForSensitiveDataInExpression((Expression) child, methodCall, filePath, violations);
            }
        });
    }
}
