package com.vigil.rules.storage;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class StorageRulesTest {

    @Test
    void testInsecureCookie_MissingBothFlags() {
        String code = """
            import javax.servlet.http.Cookie;

            public class Test {
                public void test() {
                    Cookie cookie = new Cookie("session", "abc123");
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        InsecureCookieRule rule = new InsecureCookieRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-STO-001", violations.get(0).ruleId());
        assertEquals(Severity.HIGH, violations.get(0).severity());
        assertEquals(RuleCategory.STORAGE, violations.get(0).category());
        assertTrue(violations.get(0).description().contains("setSecure()"));
        assertTrue(violations.get(0).description().contains("setHttpOnly()"));
    }

    @Test
    void testInsecureCookie_MissingSecure() {
        String code = """
            import javax.servlet.http.Cookie;

            public class Test {
                public void test() {
                    Cookie cookie = new Cookie("session", "abc123");
                    cookie.setHttpOnly(true);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        InsecureCookieRule rule = new InsecureCookieRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("setSecure()"));
        assertFalse(violations.get(0).description().contains("setHttpOnly()"));
    }

    @Test
    void testInsecureCookie_MissingHttpOnly() {
        String code = """
            import javax.servlet.http.Cookie;

            public class Test {
                public void test() {
                    Cookie cookie = new Cookie("session", "abc123");
                    cookie.setSecure(true);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        InsecureCookieRule rule = new InsecureCookieRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("setHttpOnly()"));
        assertFalse(violations.get(0).description().contains("setSecure()"));
    }

    @Test
    void testInsecureCookie_SecureConfiguration_NoViolation() {
        String code = """
            import javax.servlet.http.Cookie;

            public class Test {
                public void test() {
                    Cookie cookie = new Cookie("session", "abc123");
                    cookie.setSecure(true);
                    cookie.setHttpOnly(true);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        InsecureCookieRule rule = new InsecureCookieRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testUnencryptedFileWrite_EmailWritten() {
        String code = """
            import java.io.*;

            public class Test {
                public void test() throws IOException {
                    String userEmail = "test@example.com";
                    writer.write(userEmail);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnencryptedFileWriteRule rule = new UnencryptedFileWriteRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-STO-002", violations.get(0).ruleId());
        assertEquals(RuleCategory.STORAGE, violations.get(0).category());
        assertTrue(violations.get(0).description().contains("userEmail"));
    }

    @Test
    void testUnencryptedFileWrite_SSN_Critical() {
        String code = """
            import java.io.*;

            public class Test {
                public void test() throws IOException {
                    String ssn = "123-45-6789";
                    file.writeString(ssn);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnencryptedFileWriteRule rule = new UnencryptedFileWriteRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals(Severity.CRITICAL, violations.get(0).severity());
        assertTrue(violations.get(0).description().contains("ssn"));
    }

    @Test
    void testUnencryptedFileWrite_PhoneNumber() {
        String code = """
            import java.io.*;

            public class Test {
                public void test() throws IOException {
                    String phoneNumber = "555-1234";
                    writer.println(phoneNumber);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnencryptedFileWriteRule rule = new UnencryptedFileWriteRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("phoneNumber"));
    }

    @Test
    void testUnencryptedFileWrite_NonPii_NoViolation() {
        String code = """
            import java.io.*;

            public class Test {
                public void test() throws IOException {
                    String username = "john_doe";
                    writer.write(username);
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        UnencryptedFileWriteRule rule = new UnencryptedFileWriteRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }
}
