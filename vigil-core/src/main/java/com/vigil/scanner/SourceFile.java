package com.vigil.scanner;

import java.nio.file.Path;

public record SourceFile(Path path, Language language) {}
