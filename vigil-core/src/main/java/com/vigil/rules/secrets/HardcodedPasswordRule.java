package com.vigil.rules.secrets;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.VariableDeclarator;
import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import com.vigil.rules.Rule;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

public class HardcodedPasswordRule implements Rule {

    private static final String RULE_ID = "VIGIL-SEC-001";
    private static final String RULE_NAME = "Hardcoded Password";
    private static final Pattern PASSWORD_PATTERN = Pattern.compile(
        ".*(password|passwd|pwd|passphrase|credential).*",
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
        return RuleCategory.SECRETS;
    }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();

        cu.findAll(VariableDeclarator.class).forEach(v -> {
            String varName = v.getNameAsString();

            // Check if variable name matches password pattern
            if (PASSWORD_PATTERN.matcher(varName).matches()) {
                // Check if it has a string literal initializer
                if (v.getInitializer().isPresent() &&
                    v.getInitializer().get().isStringLiteralExpr()) {

                    int lineNumber = v.getBegin().map(p -> p.line).orElse(0);
                    String codeSnippet = v.toString();

                    violations.add(new Violation(
                        RULE_ID,
                        RULE_NAME,
                        RuleCategory.SECRETS,
                        Severity.CRITICAL,
                        filePath,
                        lineNumber,
                        codeSnippet,
                        Set.of(Framework.SOC2, Framework.GDPR, Framework.HIPAA,
                               Framework.PCI_DSS, Framework.ISO_27001),
                        "Hardcoded password detected in variable: " + varName,
                        "Store passwords in environment variables or secure credential management systems"
                    ));
                }
            }
        });

        return violations;
    }
}
