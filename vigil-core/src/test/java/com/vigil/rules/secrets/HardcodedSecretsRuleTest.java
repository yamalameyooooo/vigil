package com.vigil.rules.secrets;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class HardcodedSecretsRuleTest {

    @Test
    void testHardcodedPasswordInField() {
        String code = """
            public class Test {
                private String password = "secret123";
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        HardcodedPasswordRule rule = new HardcodedPasswordRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-SEC-001", violations.get(0).ruleId());
        assertEquals(Severity.CRITICAL, violations.get(0).severity());
        assertEquals(RuleCategory.SECRETS, violations.get(0).category());
    }

    @Test
    void testHardcodedPasswordInLocalVariable() {
        String code = """
            public class Test {
                public void test() {
                    String dbPassword = "password123";
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        HardcodedPasswordRule rule = new HardcodedPasswordRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
    }

    @Test
    void testPasswordFromEnvironment_NoViolation() {
        String code = """
            public class Test {
                private String password = System.getenv("DB_PASSWORD");
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        HardcodedPasswordRule rule = new HardcodedPasswordRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testPasswordVariableNoInitializer_NoViolation() {
        String code = """
            public class Test {
                private String password;
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        HardcodedPasswordRule rule = new HardcodedPasswordRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testHardcodedApiKeyInField() {
        String code = """
            public class Test {
                private String apiKey = "sk-1234567890";
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        HardcodedApiKeyRule rule = new HardcodedApiKeyRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-SEC-002", violations.get(0).ruleId());
        assertEquals(Severity.CRITICAL, violations.get(0).severity());
    }

    @Test
    void testHardcodedApiSecret() {
        String code = """
            public class Test {
                public void test() {
                    String api_secret = "secret-api-key-123";
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        HardcodedApiKeyRule rule = new HardcodedApiKeyRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
    }

    @Test
    void testApiKeyFromEnvironment_NoViolation() {
        String code = """
            public class Test {
                private String apiKey = System.getenv("API_KEY");
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        HardcodedApiKeyRule rule = new HardcodedApiKeyRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testHardcodedTokenInField() {
        String code = """
            public class Test {
                private String authToken = "Bearer abc123def456";
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        HardcodedTokenRule rule = new HardcodedTokenRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-SEC-003", violations.get(0).ruleId());
        assertEquals(Severity.CRITICAL, violations.get(0).severity());
    }

    @Test
    void testHardcodedPrivateKey() {
        String code = """
            public class Test {
                public void test() {
                    String private_key = "-----BEGIN PRIVATE KEY-----";
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        HardcodedTokenRule rule = new HardcodedTokenRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
    }

    @Test
    void testTokenFromEnvironment_NoViolation() {
        String code = """
            public class Test {
                private String accessToken = System.getenv("ACCESS_TOKEN");
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        HardcodedTokenRule rule = new HardcodedTokenRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testTokenVariableNoInitializer_NoViolation() {
        String code = """
            public class Test {
                private String authToken;
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        HardcodedTokenRule rule = new HardcodedTokenRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }
}
