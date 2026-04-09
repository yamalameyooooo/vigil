package com.vigil.rules.accesscontrol;

import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Violation;
import com.vigil.rules.Rule;

import java.util.List;

public class MissingAuthMiddlewareRule implements Rule {

    private static final String RULE_ID = "VIGIL-AC-002";
    private static final String RULE_NAME = "Missing Auth Middleware";

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
        return RuleCategory.ACCESS_CONTROL;
    }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        // JS/TS only - no-op for Java AST
        return List.of();
    }
}
