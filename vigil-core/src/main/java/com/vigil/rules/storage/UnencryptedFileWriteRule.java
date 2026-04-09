package com.vigil.rules.storage;

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

public class UnencryptedFileWriteRule implements Rule {

    private static final String RULE_ID = "VIGIL-STO-002";
    private static final String RULE_NAME = "Unencrypted PII File Write";
    private static final Set<String> FILE_WRITE_METHODS = Set.of(
        "write", "append", "writeString", "println", "print"
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
        return RuleCategory.STORAGE;
    }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();

        cu.findAll(MethodCallExpr.class).forEach(methodCall -> {
            String methodName = methodCall.getNameAsString();

            // Check if it's a file write method
            if (FILE_WRITE_METHODS.contains(methodName)) {
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
                    RuleCategory.STORAGE,
                    severity,
                    filePath,
                    lineNumber,
                    codeSnippet,
                    Set.of(Framework.GDPR, Framework.HIPAA, Framework.PCI_DSS, Framework.SOC2),
                    "PII written to file without encryption: " + varName,
                    "Encrypt PII before writing to disk or use encrypted storage systems"
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
