package com.vigil.cli;

import com.vigil.Vigil;
import com.vigil.report.ConsoleSummaryPrinter;
import com.vigil.report.HtmlReportGenerator;
import com.vigil.report.ReportData;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Parameters;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

@Command(
    name = "vigil",
    description = "Static analysis tool for compliance and security scanning",
    mixinStandardHelpOptions = true,
    version = "Vigil 1.0.0"
)
public class VigilCli implements Callable<Integer> {

    @Parameters(
        index = "0",
        description = "Project directory to scan",
        defaultValue = "."
    )
    private String projectDir;

    @Option(
        names = {"-o", "--output"},
        description = "Output directory for reports",
        defaultValue = "target/vigil"
    )
    private String outputDir;

    @Override
    public Integer call() {
        try {
            Path projectPath = Paths.get(projectDir).toAbsolutePath();
            Path outputPath = Paths.get(outputDir).toAbsolutePath();

            System.out.println("Starting Vigil compliance scan...");
            System.out.println("Project: " + projectPath);
            System.out.println();

            // Run scan
            Vigil vigil = new Vigil();
            ReportData reportData = vigil.scan(projectPath);

            // Generate HTML report
            HtmlReportGenerator reportGenerator = new HtmlReportGenerator();
            Path reportPath = reportGenerator.generate(reportData, outputPath);

            // Print console summary
            ConsoleSummaryPrinter printer = new ConsoleSummaryPrinter();
            printer.print(reportData, reportPath);

        } catch (Exception e) {
            System.err.println("Error during scan: " + e.getMessage());
            e.printStackTrace();
        }

        // Always return 0 (don't fail builds)
        return 0;
    }

    public static void main(String[] args) {
        int exitCode = new CommandLine(new VigilCli()).execute(args);
        System.exit(exitCode);
    }
}
