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

public class HardcodedApiKeyRule implements Rule {

    private static final String RULE_ID = "VIGIL-SEC-002";
    private static final String RULE_NAME = "Hardcoded API Key";
    private static final Pattern API_KEY_PATTERN = Pattern.compile(
        ".*(api[_-]?key|apikey|api[_-]?secret).*",
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

            // Check if variable name matches API key pattern
            if (API_KEY_PATTERN.matcher(varName).matches()) {
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
                        "Hardcoded API key detected in variable: " + varName,
                        "Store API keys in environment variables or secure credential management systems"
                    ));
                }
            }
        });

        return violations;
    }
}
