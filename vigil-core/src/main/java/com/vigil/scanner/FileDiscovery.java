package com.vigil.scanner;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class FileDiscovery {
    private static final Set<String> SKIP_DIRS = Set.of(
        "node_modules", "target", "build", "dist", ".git", ".idea", ".vscode",
        "vendor", "bin", ".gradle", "out"
    );

    public List<SourceFile> discover(Path root) throws IOException {
        List<SourceFile> sourceFiles = new ArrayList<>();
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                return SKIP_DIRS.contains(dir.getFileName().toString())
                    ? FileVisitResult.SKIP_SUBTREE
                    : FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                String name = file.getFileName().toString();
                if (name.endsWith(".java")) {
                    sourceFiles.add(new SourceFile(file, Language.JAVA));
                } else if (name.endsWith(".js")) {
                    sourceFiles.add(new SourceFile(file, Language.JAVASCRIPT));
                } else if (name.endsWith(".ts") || name.endsWith(".tsx")) {
                    sourceFiles.add(new SourceFile(file, Language.TYPESCRIPT));
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return sourceFiles;
    }

    public List<Path> discoverDependencyManifests(Path root) throws IOException {
        List<Path> manifests = new ArrayList<>();
        Files.walkFileTree(root, new SimpleFileVisitor<>() {
            @Override
            public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                return SKIP_DIRS.contains(dir.getFileName().toString())
                    ? FileVisitResult.SKIP_SUBTREE
                    : FileVisitResult.CONTINUE;
            }

            @Override
            public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                String name = file.getFileName().toString();
                if (name.equals("pom.xml") || name.equals("package.json")) {
                    manifests.add(file);
                }
                return FileVisitResult.CONTINUE;
            }
        });
        return manifests;
    }
}
