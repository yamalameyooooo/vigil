package com.vigil.report;

import java.io.IOException;
import java.nio.file.Path;

public interface ReportGenerator {
    Path generate(ReportData data, Path outputDir) throws IOException;
}
