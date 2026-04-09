package com.vigil.rules.pii;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class PiiRulesTest {

    @Test
    void testPiiInLogs_EmailLogged() {
        String code = """
            public class Test {
                public void test() {
                    String userEmail = "test@example.com";
                    logger.info(userEmail);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        PiiInLogsRule rule = new PiiInLogsRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-PII-001", violations.get(0).ruleId());
        assertEquals(RuleCategory.PII, violations.get(0).category());
        assertTrue(violations.get(0).description().contains("userEmail"));
    }

    @Test
    void testPiiInLogs_SSNLogged_Critical() {
        String code = """
            public class Test {
                public void test() {
                    String ssn = "123-45-6789";
                    System.out.println(ssn);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        PiiInLogsRule rule = new PiiInLogsRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals(Severity.CRITICAL, violations.get(0).severity());
        assertTrue(violations.get(0).description().contains("ssn"));
    }

    @Test
    void testPiiInLogs_NonPiiLogged_NoViolation() {
        String code = """
            public class Test {
                public void test() {
                    String username = "john_doe";
                    logger.info(username);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        PiiInLogsRule rule = new PiiInLogsRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testPiiInCookies_EmailInCookie() {
        String code = """
            import javax.servlet.http.Cookie;

            public class Test {
                public void test() {
                    String userEmail = "test@example.com";
                    Cookie cookie = new Cookie("email", userEmail);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        PiiInCookiesRule rule = new PiiInCookiesRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-PII-002", violations.get(0).ruleId());
        assertEquals(RuleCategory.PII, violations.get(0).category());
        assertTrue(violations.get(0).description().contains("userEmail"));
    }

    @Test
    void testPiiInCookies_CreditCardInCookie_Critical() {
        String code = """
            import javax.servlet.http.Cookie;

            public class Test {
                public void test() {
                    String creditCard = "4111111111111111";
                    Cookie cookie = new Cookie("cc", creditCard);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        PiiInCookiesRule rule = new PiiInCookiesRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals(Severity.CRITICAL, violations.get(0).severity());
    }

    @Test
    void testPiiInCookies_NonPii_NoViolation() {
        String code = """
            import javax.servlet.http.Cookie;

            public class Test {
                public void test() {
                    String sessionId = "abc123";
                    Cookie cookie = new Cookie("session", sessionId);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        PiiInCookiesRule rule = new PiiInCookiesRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testUnmaskedPiiResponse_PhoneReturned() {
        String code = """
            import org.springframework.web.bind.annotation.*;

            @RestController
            public class Test {
                @GetMapping("/user")
                public String getUser() {
                    String phoneNumber = "555-1234";
                    return phoneNumber;
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnmaskedPiiResponseRule rule = new UnmaskedPiiResponseRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-PII-003", violations.get(0).ruleId());
        assertEquals(RuleCategory.PII, violations.get(0).category());
        assertTrue(violations.get(0).description().contains("phoneNumber"));
    }

    @Test
    void testUnmaskedPiiResponse_NonController_NoViolation() {
        String code = """
            public class Test {
                public String getUser() {
                    String phoneNumber = "555-1234";
                    return phoneNumber;
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnmaskedPiiResponseRule rule = new UnmaskedPiiResponseRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testUnmaskedPiiResponse_NonPii_NoViolation() {
        String code = """
            import org.springframework.web.bind.annotation.*;

            @RestController
            public class Test {
                @GetMapping("/user")
                public String getUser() {
                    String userId = "12345";
                    return userId;
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnmaskedPiiResponseRule rule = new UnmaskedPiiResponseRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }
}
