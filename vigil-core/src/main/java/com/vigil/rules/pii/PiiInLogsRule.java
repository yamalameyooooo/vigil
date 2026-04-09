package com.vigil.rules.pii;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.NameExpr;
import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import com.vigil.rules.PiiFieldDetector;
import com.vigil.rules.Rule;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class PiiInLogsRule implements Rule {

    private static final String RULE_ID = "VIGIL-PII-001";
    private static final String RULE_NAME = "PII in Logs";
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
        return RuleCategory.PII;
    }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();

        cu.findAll(MethodCallExpr.class).forEach(methodCall -> {
            String methodName = methodCall.getNameAsString();

            // Check if it's a logging method
            if (LOG_METHODS.contains(methodName)) {
                // Check arguments for PII variable names
                for (Expression arg : methodCall.getArguments()) {
                    checkForPiiInExpression(arg, methodCall, filePath, violations);
                }
            }
        });

        return violations;
    }

    private void checkForPiiInExpression(Expression expr, MethodCallExpr methodCall,
                                         String filePath, List<Violation> violations) {
        if (expr instanceof NameExpr) {
            NameExpr nameExpr = (NameExpr) expr;
            String varName = nameExpr.getNameAsString();

            if (PiiFieldDetector.isPiiName(varName)) {
                int lineNumber = methodCall.getBegin().map(p -> p.line).orElse(0);
                String codeSnippet = methodCall.toString();
                Severity severity = PiiFieldDetector.getSeverity(varName);

                violations.add(new Violation(
                    RULE_ID,
                    RULE_NAME,
                    RuleCategory.PII,
                    severity,
                    filePath,
                    lineNumber,
                    codeSnippet,
                    Set.of(Framework.GDPR, Framework.HIPAA, Framework.CCPA,
                           Framework.LGPD, Framework.POPIA),
                    "PII field logged without masking: " + varName,
                    "Mask or redact PII before logging, or use structured logging with PII filters"
                ));
            }
        }

        // Recursively check nested expressions
        expr.getChildNodes().forEach(child -> {
            if (child instanceof Expression) {
                checkForPiiInExpression((Expression) child, methodCall, filePath, violations);
            }
        });
    }
}
