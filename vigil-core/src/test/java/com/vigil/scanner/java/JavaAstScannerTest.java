package com.vigil.scanner.java;

import com.vigil.rules.*;
import com.github.javaparser.ast.CompilationUnit;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class JavaAstScannerTest {
    @Test
    void shouldParseJavaSourceAndRunRules() {
        String source = "public class UserService { private String password = \"admin123\"; }";

        Rule testRule = new Rule() {
            @Override
            public String getId() {
                return "TEST-001";
            }

            @Override
            public String getName() {
                return "Test Rule";
            }

            @Override
            public RuleCategory getCategory() {
                return RuleCategory.SECRETS;
            }

            @Override
            public List<Violation> check(CompilationUnit cu, String filePath) {
                List<Violation> violations = new java.util.ArrayList<>();
                cu.findAll(com.github.javaparser.ast.body.VariableDeclarator.class).forEach(v -> {
                    if (v.getNameAsString().equalsIgnoreCase("password")
                            && v.getInitializer().isPresent()
                            && v.getInitializer().get().isStringLiteralExpr()) {
                        violations.add(new Violation(
                            getId(),
                            getName(),
                            getCategory(),
                            Severity.CRITICAL,
                            filePath,
                            v.getBegin().map(p -> p.line).orElse(0),
                            v.toString(),
                            Set.of(Framework.SOC2),
                            "Hardcoded password",
                            "Use env vars"
                        ));
                    }
                });
                return violations;
            }
        };

        RuleRegistry registry = new RuleRegistry();
        registry.register(testRule);

        JavaAstScanner scanner = new JavaAstScanner(registry);
        List<Violation> violations = scanner.scan(source, "UserService.java");

        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).ruleId()).isEqualTo("TEST-001");
    }

    @Test
    void shouldReturnEmptyForUnparseableSource() {
        assertThat(new JavaAstScanner(new RuleRegistry())
            .scan("not valid java {{{{", "Bad.java"))
            .isEmpty();
    }
}
