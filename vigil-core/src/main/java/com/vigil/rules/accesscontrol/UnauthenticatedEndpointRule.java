package com.vigil.rules.accesscontrol;

import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.body.ClassOrInterfaceDeclaration;
import com.vigil.rules.Framework;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import com.vigil.rules.Rule;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class UnauthenticatedEndpointRule implements Rule {

    private static final String RULE_ID = "VIGIL-AC-001";
    private static final String RULE_NAME = "Unauthenticated Endpoint";
    private static final Set<String> CONTROLLER_ANNOTATIONS = Set.of(
        "RestController", "Controller"
    );
    private static final Set<String> MAPPING_ANNOTATIONS = Set.of(
        "GetMapping", "PostMapping", "PutMapping", "DeleteMapping", "PatchMapping", "RequestMapping"
    );
    private static final Set<String> SECURITY_ANNOTATIONS = Set.of(
        "PreAuthorize", "Secured", "RolesAllowed", "PermitAll", "DenyAll"
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
        return RuleCategory.ACCESS_CONTROL;
    }

    @Override
    public List<Violation> check(CompilationUnit cu, String filePath) {
        List<Violation> violations = new ArrayList<>();

        cu.findAll(ClassOrInterfaceDeclaration.class).forEach(classDecl -> {
            // Check if class has @RestController or @Controller
            boolean isController = classDecl.getAnnotations().stream()
                .anyMatch(ann -> CONTROLLER_ANNOTATIONS.contains(ann.getNameAsString()));

            if (isController) {
                // Check if class has class-level security annotation
                boolean hasClassLevelSecurity = classDecl.getAnnotations().stream()
                    .anyMatch(ann -> SECURITY_ANNOTATIONS.contains(ann.getNameAsString()));

                // Skip if class has global security applied
                if (!hasClassLevelSecurity) {
                    // Check each method with mapping annotations
                    classDecl.getMethods().forEach(method -> {
                        boolean isEndpoint = method.getAnnotations().stream()
                            .anyMatch(ann -> MAPPING_ANNOTATIONS.contains(ann.getNameAsString()));

                        if (isEndpoint) {
                            // Check if method has security annotation
                            boolean hasMethodSecurity = method.getAnnotations().stream()
                                .anyMatch(ann -> SECURITY_ANNOTATIONS.contains(ann.getNameAsString()));

                            if (!hasMethodSecurity) {
                                int lineNumber = method.getBegin().map(p -> p.line).orElse(0);
                                String codeSnippet = method.getDeclarationAsString();

                                violations.add(new Violation(
                                    RULE_ID,
                                    RULE_NAME,
                                    RuleCategory.ACCESS_CONTROL,
                                    Severity.HIGH,
                                    filePath,
                                    lineNumber,
                                    codeSnippet,
                                    Set.of(Framework.SOC2, Framework.PCI_DSS,
                                           Framework.HIPAA, Framework.ISO_27001),
                                    "Endpoint lacks authentication/authorization: " + method.getNameAsString(),
                                    "Add @PreAuthorize, @Secured, or @RolesAllowed annotation to enforce access control"
                                ));
                            }
                        }
                    });
                }
            }
        });

        return violations;
    }
}
