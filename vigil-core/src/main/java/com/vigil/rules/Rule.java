package com.vigil.rules;

import com.github.javaparser.ast.CompilationUnit;
import java.util.List;

public interface Rule {
    String getId();
    String getName();
    RuleCategory getCategory();
    List<Violation> check(CompilationUnit cu, String filePath);
}
