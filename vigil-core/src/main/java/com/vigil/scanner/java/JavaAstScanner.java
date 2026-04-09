package com.vigil.scanner.java;

import com.github.javaparser.JavaParser;
import com.github.javaparser.ParseResult;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.Rule;
import com.vigil.rules.RuleRegistry;
import com.vigil.rules.Violation;

import java.util.ArrayList;
import java.util.List;

public class JavaAstScanner {
    private final RuleRegistry registry;

    public JavaAstScanner(RuleRegistry registry) {
        this.registry = registry;
    }

    public List<Violation> scan(String source, String filePath) {
        JavaParser parser = new JavaParser();
        ParseResult<CompilationUnit> result = parser.parse(source);

        if (!result.isSuccessful() || result.getResult().isEmpty()) {
            return List.of();
        }

        CompilationUnit cu = result.getResult().get();
        List<Violation> violations = new ArrayList<>();

        for (Rule rule : registry.getAllRules()) {
            violations.addAll(rule.check(cu, filePath));
        }

        return violations;
    }
}
