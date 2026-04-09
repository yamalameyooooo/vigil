package com.vigil.scanner;

import com.vigil.rules.RuleRegistry;
import com.vigil.rules.Violation;
import com.vigil.scanner.java.JavaAstScanner;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class Scanner {
    private final RuleRegistry registry;
    private final FileDiscovery discovery = new FileDiscovery();

    public Scanner(RuleRegistry registry) {
        this.registry = registry;
    }

    public List<Violation> scan(Path projectRoot) throws IOException {
        List<SourceFile> sourceFiles = discovery.discover(projectRoot);
        JavaAstScanner javaScanner = new JavaAstScanner(registry);

        // Scan Java files in parallel
        return sourceFiles.parallelStream()
            .filter(sf -> sf.language() == Language.JAVA)
            .flatMap(sf -> {
                try {
                    String source = Files.readString(sf.path());
                    return javaScanner.scan(source, sf.path().toString()).stream();
                } catch (IOException e) {
                    return new ArrayList<Violation>().stream();
                }
            })
            .toList();
    }
}
