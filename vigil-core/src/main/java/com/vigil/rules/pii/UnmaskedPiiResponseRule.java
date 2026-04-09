package com.vigil.rules.pii;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.github.javaparser.ast.body.MethodDeclaration;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.NameExpr;
import com.github.javaparser.ast.stmt.ReturnStmt;
import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import com.vigil.rules.PiiFieldDetector;
import com.vigil.rules.Rule;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class UnmaskedPiiResponseRule implements Rule {

    private static final String RULE_ID = "VIGIL-PII-003";
    private static final String RULE_NAME = "Unmasked PII in API Response";
    private static final Set<String> CONTROLLER_ANNOTATIONS = Set.of(
        "RestController", "Controller"
    );
    private static final Set<String> MAPPING_ANNOTATIONS = Set.of(
        "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping"
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

        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(classDecl -> {
            // Check if class has @RestController or @Controller
            boolean isController = classDecl.getAnnotations().stream()
                .anyMatch(ann -> CONTROLLER_ANNOTATIONS.contains(ann.getNameAsString()));

            if (isController) {
                // Check each method with mapping annotations
                classDecl.getMethods().forEach(method -> {
                    boolean isEndpoint = method.getAnnotations().stream()
                        .anyMatch(ann -> MAPPING_ANNOTATIONS.contains(ann.getNameAsString()));

                    if (isEndpoint) {
                        checkMethodForPiiReturns(method, filePath, violations);
                    }
                });
            }
        });

        return violations;
    }

    private void checkMethodForPiiReturns(MethodDeclaration method, String filePath,
                                          List<Violation> violations) {
        method.findAll(ReturnStmt.class).forEach(returnStmt -> {
            if (returnStmt.getExpression().isPresent()) {
                Expression returnExpr = returnStmt.getExpression().get();
                checkForPiiInExpression(returnExpr, returnStmt, filePath, violations);
            }
        });
    }

    private void checkForPiiInExpression(Expression expr, ReturnStmt returnStmt,
                                         String filePath, List<Violation> violations) {
        if (expr instanceof NameExpr) {
            NameExpr nameExpr = (NameExpr) expr;
            String varName = nameExpr.getNameAsString();

            if (PiiFieldDetector.isPiiName(varName)) {
                int lineNumber = returnStmt.getBegin().map(p -> p.line).orElse(0);
                String codeSnippet = returnStmt.toString();
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
                    "Unmasked PII returned in API response: " + varName,
                    "Mask sensitive PII fields (e.g., show only last 4 digits) or use DTOs with selective field exposure"
                ));
            }
        }

        // Recursively check nested expressions
        expr.getChildNodes().forEach(child -> {
            if (child instanceof Expression) {
                checkForPiiInExpression((Expression) child, returnStmt, filePath, violations);
            }
        });
    }
}
