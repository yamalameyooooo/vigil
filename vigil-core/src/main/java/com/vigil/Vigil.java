package com.vigil;

import com.vigil.dependencies.DependencyAnalyzer;
import com.vigil.report.ReportData;
import com.vigil.rules.RuleRegistry;
import com.vigil.rules.Violation;
import com.vigil.rules.accesscontrol.MissingAuthMiddlewareRule;
import com.vigil.rules.accesscontrol.UnauthenticatedEndpointRule;
import com.vigil.rules.encryption.WeakCipherRule;
import com.vigil.rules.encryption.WeakHashAlgorithmRule;
import com.vigil.rules.encryption.WeakTlsRule;
import com.vigil.rules.logging.MissingAuditLogRule;
import com.vigil.rules.logging.SensitiveDataInLogsRule;
import com.vigil.rules.pii.PiiInCookiesRule;
import com.vigil.rules.pii.PiiInLogsRule;
import com.vigil.rules.pii.UnmaskedPiiResponseRule;
import com.vigil.rules.secrets.HardcodedApiKeyRule;
import com.vigil.rules.secrets.HardcodedPasswordRule;
import com.vigil.rules.secrets.HardcodedTokenRule;
import com.vigil.rules.storage.InsecureCookieRule;
import com.vigil.rules.storage.UnencryptedFileWriteRule;
import com.vigil.scanner.FileDiscovery;
import com.vigil.scanner.Scanner;

import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

public class Vigil {
    private final RuleRegistry registry;
    private final Scanner scanner;
    private final DependencyAnalyzer dependencyAnalyzer;
    private final FileDiscovery fileDiscovery;

    public Vigil() {
        this.registry = new RuleRegistry();
        registerAllRules();
        this.scanner = new Scanner(registry);
        this.dependencyAnalyzer = new DependencyAnalyzer();
        this.fileDiscovery = new FileDiscovery();
    }

    private void registerAllRules() {
        // Secrets rules
        registry.register(new HardcodedPasswordRule());
        registry.register(new HardcodedApiKeyRule());
        registry.register(new HardcodedTokenRule());

        // PII rules
        registry.register(new PiiInLogsRule());
        registry.register(new PiiInCookiesRule());
        registry.register(new UnmaskedPiiResponseRule());

        // Encryption rules
        registry.register(new WeakHashAlgorithmRule());
        registry.register(new WeakCipherRule());
        registry.register(new WeakTlsRule());

        // Logging rules
        registry.register(new SensitiveDataInLogsRule());
        registry.register(new MissingAuditLogRule());

        // Storage rules
        registry.register(new UnencryptedFileWriteRule());
        registry.register(new InsecureCookieRule());

        // Access control rules
        registry.register(new UnauthenticatedEndpointRule());
        registry.register(new MissingAuthMiddlewareRule());
    }

    public ReportData scan(Path projectRoot) throws IOException {
        List<Violation> allViolations = new ArrayList<>();

        // Scan source files
        List<Violation> sourceViolations = scanner.scan(projectRoot);
        allViolations.addAll(sourceViolations);

        // Scan dependencies
        List<Path> manifests = fileDiscovery.discoverDependencyManifests(projectRoot);
        List<Violation> dependencyViolations = dependencyAnalyzer.analyze(manifests);
        allViolations.addAll(dependencyViolations);

        // Count files scanned
        int filesScanned = fileDiscovery.discover(projectRoot).size() + manifests.size();

        return new ReportData(
            projectRoot.getFileName().toString(),
            LocalDateTime.now(),
            filesScanned,
            allViolations
        );
    }
}
