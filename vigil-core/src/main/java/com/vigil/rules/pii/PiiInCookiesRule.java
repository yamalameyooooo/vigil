package com.vigil.rules.pii;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import com.vigil.rules.PiiFieldDetector;
import com.vigil.rules.Rule;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class PiiInCookiesRule implements Rule {

    private static final String RULE_ID = "VIGIL-PII-002";
    private static final String RULE_NAME = "PII in Cookies";

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

        cu.findAll(ObjectCreationExpr.class).forEach(objCreation -> {
            // Check if it's new Cookie(...)
            if (objCreation.getType().getNameAsString().equals("Cookie")) {
                if (objCreation.getArguments().size() >= 2) {
                    Expression valueArg = objCreation.getArgument(1);
                    checkForPiiInExpression(valueArg, objCreation, filePath, violations);
                }
            }
        });

        return violations;
    }

    private void checkForPiiInExpression(Expression expr, ObjectCreationExpr objCreation,
                                         String filePath, List<Violation> violations) {
        if (expr instanceof NameExpr) {
            NameExpr nameExpr = (NameExpr) expr;
            String varName = nameExpr.getNameAsString();

            if (PiiFieldDetector.isPiiName(varName)) {
                int lineNumber = objCreation.getBegin().map(p -> p.line).orElse(0);
                String codeSnippet = objCreation.toString();
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
                    "PII field stored in cookie without encryption: " + varName,
                    "Do not store PII in cookies. Use session IDs instead and keep PII server-side"
                ));
            }
        }

        // Recursively check nested expressions
        expr.getChildNodes().forEach(child -> {
            if (child instanceof Expression) {
                checkForPiiInExpression((Expression) child, objCreation, filePath, violations);
            }
        });
    }
}
