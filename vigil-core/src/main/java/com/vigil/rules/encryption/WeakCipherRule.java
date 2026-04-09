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

public class WeakCipherRule implements Rule {

    private static final String RULE_ID = "VIGIL-ENC-002";
    private static final String RULE_NAME = "Weak Cipher Algorithm";

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
            // Check if it's Cipher.getInstance(...)
            if (methodCall.getNameAsString().equals("getInstance")) {
                if (methodCall.getScope().isPresent()) {
                    String scope = methodCall.getScope().get().toString();
                    if (scope.equals("Cipher")) {
                        // Check the first argument
                        if (!methodCall.getArguments().isEmpty()) {
                            Expression arg = methodCall.getArgument(0);
                            if (arg instanceof StringLiteralExpr) {
                                String transformation = ((StringLiteralExpr) arg).getValue().toUpperCase();

                                boolean isWeak = false;
                                String reason = "";

                                // Check for weak cipher algorithms
                                if (transformation.startsWith("DES/") || transformation.equals("DES")) {
                                    isWeak = true;
                                    reason = "DES is cryptographically broken";
                                } else if (transformation.startsWith("RC4/") || transformation.equals("RC4")) {
                                    isWeak = true;
                                    reason = "RC4 has known vulnerabilities";
                                } else if (transformation.startsWith("BLOWFISH/") || transformation.equals("BLOWFISH")) {
                                    isWeak = true;
                                    reason = "Blowfish has a small block size (64-bit)";
                                } else if (transformation.contains("/ECB/")) {
                                    isWeak = true;
                                    reason = "ECB mode is insecure (does not provide semantic security)";
                                }

                                if (isWeak) {
                                    int lineNumber = methodCall.getBegin().map(p -> p.line).orElse(0);
                                    String codeSnippet = methodCall.toString();

                                    violations.add(new Violation(
                                        RULE_ID,
                                        RULE_NAME,
                                        RuleCategory.ENCRYPTION,
                                        Severity.CRITICAL,
                                        filePath,
                                        lineNumber,
                                        codeSnippet,
                                        Set.of(Framework.PCI_DSS, Framework.HIPAA,
                                               Framework.SOC2, Framework.ISO_27001),
                                        "Weak cipher detected: " + transformation + " - " + reason,
                                        "Use AES/GCM/NoPadding or AES/CBC/PKCS5Padding with proper IV"
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
