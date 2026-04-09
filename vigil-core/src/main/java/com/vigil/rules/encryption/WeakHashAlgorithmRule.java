package com.vigil.rules.encryption;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.Expression;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import com.vigil.rules.Rule;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class WeakHashAlgorithmRule implements Rule {

    private static final String RULE_ID = "VIGIL-ENC-001";
    private static final String RULE_NAME = "Weak Hash Algorithm";
    private static final Set<String> WEAK_ALGORITHMS = Set.of("MD5", "SHA1", "SHA-1");

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
        return RuleCategory.ENCRYPTION;
    }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();

        cu.findAll(MethodCallExpr.class).forEach(methodCall -> {
            // Check if it's MessageDigest.getInstance(...)
            if (methodCall.getNameAsString().equals("getInstance")) {
                if (methodCall.getScope().isPresent()) {
                    String scope = methodCall.getScope().get().toString();
                    if (scope.equals("MessageDigest")) {
                        // Check the first argument
                        if (!methodCall.getArguments().isEmpty()) {
                            Expression arg = methodCall.getArgument(0);
                            if (arg instanceof StringLiteralExpr) {
                                String algorithm = ((StringLiteralExpr) arg).getValue();
                                if (WEAK_ALGORITHMS.contains(algorithm)) {
                                    int lineNumber = methodCall.getBegin().map(p -> p.line).orElse(0);
                                    String codeSnippet = methodCall.toString();

                                    violations.add(new Violation(
                                        RULE_ID,
                                        RULE_NAME,
                                        RuleCategory.ENCRYPTION,
                                        Severity.HIGH,
                                        filePath,
                                        lineNumber,
                                        codeSnippet,
                                        Set.of(Framework.PCI_DSS, Framework.HIPAA,
                                               Framework.SOC2, Framework.ISO_27001),
                                        "Weak hash algorithm detected: " + algorithm,
                                        "Use SHA-256, SHA-384, or SHA-512 instead"
                                    ));
                                }
                            }
                        }
                    }
                }
            }
        });

        return violations;
    }
}
