package com.vigil.rules.accesscontrol;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AccessControlRulesTest {

    @Test
    void testUnauthenticatedEndpoint_NoSecurity() {
        String code = """
            import org.springframework.web.bind.annotation.*;

            @RestController
            public class Test {
                @GetMapping("/user")
                public String getUser() {
                    return "user";
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnauthenticatedEndpointRule rule = new UnauthenticatedEndpointRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-AC-001", violations.get(0).ruleId());
        assertEquals(Severity.HIGH, violations.get(0).severity());
        assertEquals(RuleCategory.ACCESS_CONTROL, violations.get(0).category());
        assertTrue(violations.get(0).description().contains("getUser"));
    }

    @Test
    void testUnauthenticatedEndpoint_PostMapping() {
        String code = """
            import org.springframework.web.bind.annotation.*;

            @RestController
            public class Test {
                @PostMapping("/user")
                public String createUser() {
                    return "created";
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnauthenticatedEndpointRule rule = new UnauthenticatedEndpointRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("createUser"));
    }

    @Test
    void testUnauthenticatedEndpoint_WithMethodSecurity_NoViolation() {
        String code = """
            import org.springframework.web.bind.annotation.*;
            import org.springframework.security.access.prepost.PreAuthorize;

            @RestController
            public class Test {
                @GetMapping("/user")
                @PreAuthorize("hasRole('USER')")
                public String getUser() {
                    return "user";
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnauthenticatedEndpointRule rule = new UnauthenticatedEndpointRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testUnauthenticatedEndpoint_WithClassLevelSecurity_NoViolation() {
        String code = """
            import org.springframework.web.bind.annotation.*;
            import org.springframework.security.access.prepost.PreAuthorize;

            @RestController
            @PreAuthorize("hasRole('ADMIN')")
            public class Test {
                @GetMapping("/user")
                public String getUser() {
                    return "user";
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnauthenticatedEndpointRule rule = new UnauthenticatedEndpointRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testUnauthenticatedEndpoint_RegularClass_NoViolation() {
        String code = """
            public class Test {
                public String getUser() {
                    return "user";
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnauthenticatedEndpointRule rule = new UnauthenticatedEndpointRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testUnauthenticatedEndpoint_SecuredAnnotation_NoViolation() {
        String code = """
            import org.springframework.web.bind.annotation.*;
            import org.springframework.security.access.annotation.Secured;

            @RestController
            public class Test {
                @GetMapping("/user")
                @Secured("ROLE_USER")
                public String getUser() {
                    return "user";
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnauthenticatedEndpointRule rule = new UnauthenticatedEndpointRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testMissingAuthMiddleware_NoOpForJava() {
        String code = """
            public class Test {
                public void test() {
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        MissingAuthMiddlewareRule rule = new MissingAuthMiddlewareRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }
}
