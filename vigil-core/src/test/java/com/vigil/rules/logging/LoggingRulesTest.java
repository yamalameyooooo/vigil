package com.vigil.rules.logging;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class LoggingRulesTest {

    @Test
    void testSensitiveDataInLogs_Password() {
        String code = """
            public class Test {
                public void test() {
                    String password = "secret123";
                    logger.info(password);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        SensitiveDataInLogsRule rule = new SensitiveDataInLogsRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-LOG-001", violations.get(0).ruleId());
        assertEquals(Severity.HIGH, violations.get(0).severity());
        assertEquals(RuleCategory.LOGGING, violations.get(0).category());
        assertTrue(violations.get(0).description().contains("password"));
    }

    @Test
    void testSensitiveDataInLogs_CreditCard() {
        String code = """
            public class Test {
                public void test() {
                    String creditCard = "4111111111111111";
                    System.out.println(creditCard);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        SensitiveDataInLogsRule rule = new SensitiveDataInLogsRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("creditCard"));
    }

    @Test
    void testSensitiveDataInLogs_PrivateKey() {
        String code = """
            public class Test {
                public void test() {
                    String privateKey = "-----BEGIN RSA PRIVATE KEY-----";
                    logger.debug(privateKey);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        SensitiveDataInLogsRule rule = new SensitiveDataInLogsRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("privateKey"));
    }

    @Test
    void testSensitiveDataInLogs_NonSensitive_NoViolation() {
        String code = """
            public class Test {
                public void test() {
                    String username = "john_doe";
                    logger.info(username);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        SensitiveDataInLogsRule rule = new SensitiveDataInLogsRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testMissingAuditLog_LoginMethod() {
        String code = """
            public class Test {
                public void login(String username, String password) {
                    // Authentication logic without logging
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        MissingAuditLogRule rule = new MissingAuditLogRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-LOG-002", violations.get(0).ruleId());
        assertEquals(Severity.MEDIUM, violations.get(0).severity());
        assertEquals(RuleCategory.LOGGING, violations.get(0).category());
        assertTrue(violations.get(0).description().contains("login"));
    }

    @Test
    void testMissingAuditLog_DeleteUserMethod() {
        String code = """
            public class Test {
                public void deleteUser(String userId) {
                    // Delete user without logging
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        MissingAuditLogRule rule = new MissingAuditLogRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("deleteUser"));
    }

    @Test
    void testMissingAuditLog_LoginWithLogging_NoViolation() {
        String code = """
            public class Test {
                public void login(String username, String password) {
                    logger.info("User login attempt: " + username);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        MissingAuditLogRule rule = new MissingAuditLogRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testMissingAuditLog_RegularMethod_NoViolation() {
        String code = """
            public class Test {
                public void processData(String data) {
                    // Regular method without logging
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        MissingAuditLogRule rule = new MissingAuditLogRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testMissingAuditLog_ChangePasswordMethod() {
        String code = """
            public class Test {
                public void changePassword(String oldPassword, String newPassword) {
                    // Change password logic
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        MissingAuditLogRule rule = new MissingAuditLogRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("changePassword"));
    }
}
