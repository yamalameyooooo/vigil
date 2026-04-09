package com.vigil.rules.storage;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.ObjectCreationExpr;
import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import com.vigil.rules.Rule;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class InsecureCookieRule implements Rule {

    private static final String RULE_ID = "VIGIL-STO-001";
    private static final String RULE_NAME = "Insecure Cookie Configuration";

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

        cu.findAll(MethodDeclaration.class).forEach(method -> {
            // Find all Cookie creations in this method
            List<ObjectCreationExpr> cookieCreations = method.findAll(ObjectCreationExpr.class)
                .stream()
                .filter(obj -> obj.getType().getNameAsString().equals("Cookie"))
                .toList();

            for (ObjectCreationExpr cookieCreation : cookieCreations) {
                // Check if setSecure() is called in the same method
                boolean hasSetSecure = method.findAll(MethodCallExpr.class).stream()
                    .anyMatch(call -> call.getNameAsString().equals("setSecure"));

                // Check if setHttpOnly() is called in the same method
                boolean hasSetHttpOnly = method.findAll(MethodCallExpr.class).stream()
                    .anyMatch(call -> call.getNameAsString().equals("setHttpOnly"));

                if (!hasSetSecure || !hasSetHttpOnly) {
                    int lineNumber = cookieCreation.getBegin().map(p -> p.line).orElse(0);
                    String codeSnippet = cookieCreation.toString();

                    String missingFlags = "";
                    if (!hasSetSecure && !hasSetHttpOnly) {
                        missingFlags = "setSecure() and setHttpOnly()";
                    } else if (!hasSetSecure) {
                        missingFlags = "setSecure()";
                    } else {
                        missingFlags = "setHttpOnly()";
                    }

                    violations.add(new Violation(
                        RULE_ID,
                        RULE_NAME,
                        RuleCategory.STORAGE,
                        Severity.HIGH,
                        filePath,
                        lineNumber,
                        codeSnippet,
                        Set.of(Framework.GDPR, Framework.HIPAA, Framework.PCI_DSS, Framework.SOC2),
                        "Cookie created without proper security flags: missing " + missingFlags,
                        "Always call setSecure(true) and setHttpOnly(true) on cookies to prevent interception and XSS"
                    ));
                }
            }
        });

        return violations;
    }
}
