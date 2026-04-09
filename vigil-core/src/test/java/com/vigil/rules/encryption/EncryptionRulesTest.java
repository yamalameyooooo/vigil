package com.vigil.rules.encryption;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.vigil.rules.RuleCategory;
import com.vigil.rules.Severity;
import com.vigil.rules.Violation;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class EncryptionRulesTest {

    @Test
    void testWeakHashAlgorithm_MD5() {
        String code = """
            import java.security.MessageDigest;

            public class Test {
                public void test() throws Exception {
                    MessageDigest md = MessageDigest.getInstance("MD5");
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        WeakHashAlgorithmRule rule = new WeakHashAlgorithmRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-ENC-001", violations.get(0).ruleId());
        assertEquals(Severity.HIGH, violations.get(0).severity());
        assertEquals(RuleCategory.ENCRYPTION, violations.get(0).category());
        assertTrue(violations.get(0).description().contains("MD5"));
    }

    @Test
    void testWeakHashAlgorithm_SHA1() {
        String code = """
            import java.security.MessageDigest;

            public class Test {
                public void test() throws Exception {
                    MessageDigest md = MessageDigest.getInstance("SHA1");
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        WeakHashAlgorithmRule rule = new WeakHashAlgorithmRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("SHA1"));
    }

    @Test
    void testStrongHashAlgorithm_NoViolation() {
        String code = """
            import java.security.MessageDigest;

            public class Test {
                public void test() throws Exception {
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        WeakHashAlgorithmRule rule = new WeakHashAlgorithmRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testWeakCipher_DES() {
        String code = """
            import javax.crypto.Cipher;

            public class Test {
                public void test() throws Exception {
                    Cipher cipher = Cipher.getInstance("DES/CBC/PKCS5Padding");
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        WeakCipherRule rule = new WeakCipherRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-ENC-002", violations.get(0).ruleId());
        assertEquals(Severity.CRITICAL, violations.get(0).severity());
        assertTrue(violations.get(0).description().contains("DES"));
    }

    @Test
    void testWeakCipher_RC4() {
        String code = """
            import javax.crypto.Cipher;

            public class Test {
                public void test() throws Exception {
                    Cipher cipher = Cipher.getInstance("RC4");
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        WeakCipherRule rule = new WeakCipherRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("RC4"));
    }

    @Test
    void testWeakCipher_ECB() {
        String code = """
            import javax.crypto.Cipher;

            public class Test {
                public void test() throws Exception {
                    Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        WeakCipherRule rule = new WeakCipherRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("ECB"));
    }

    @Test
    void testStrongCipher_NoViolation() {
        String code = """
            import javax.crypto.Cipher;

            public class Test {
                public void test() throws Exception {
                    Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        WeakCipherRule rule = new WeakCipherRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }

    @Test
    void testWeakTls_SSLv3() {
        String code = """
            import javax.net.ssl.SSLContext;

            public class Test {
                public void test() throws Exception {
                    SSLContext context = SSLContext.getInstance("SSLv3");
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        WeakTlsRule rule = new WeakTlsRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertEquals("VIGIL-ENC-003", violations.get(0).ruleId());
        assertEquals(Severity.CRITICAL, violations.get(0).severity());
        assertTrue(violations.get(0).description().contains("SSLv3"));
    }

    @Test
    void testWeakTls_TLSv1() {
        String code = """
            import javax.net.ssl.SSLContext;

            public class Test {
                public void test() throws Exception {
                    SSLContext context = SSLContext.getInstance("TLSv1");
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        WeakTlsRule rule = new WeakTlsRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(1, violations.size());
        assertTrue(violations.get(0).description().contains("TLSv1"));
    }

    @Test
    void testStrongTls_NoViolation() {
        String code = """
            import javax.net.ssl.SSLContext;

            public class Test {
                public void test() throws Exception {
                    SSLContext context = SSLContext.getInstance("TLSv1.2");
                }
            }
            """;

        CompilationUnit cu = StaticJavaParser.parse(code);
        WeakTlsRule rule = new WeakTlsRule();
        List<Violation> violations = rule.check(cu, "Test.java");

        assertEquals(0, violations.size());
    }
}
