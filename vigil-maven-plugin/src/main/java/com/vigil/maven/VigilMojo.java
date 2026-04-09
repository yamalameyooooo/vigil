package com.vigil.maven;

import com.vigil.Vigil;
import com.vigil.report.ConsoleSummaryPrinter;
import com.vigil.report.HtmlReportGenerator;
import com.vigil.report.ReportData;
import org.apache.maven.plugin.AbstractMojo;
import org.apache.maven.plugin.MojoExecutionException;
import org.apache.maven.plugin.MojoFailureException;
import org.apache.maven.plugins.annotations.LifecyclePhase;
import org.apache.maven.plugins.annotations.Mojo;
import org.apache.maven.plugins.annotations.Parameter;

import java.io.File;
import java.nio.file.Path;

@Mojo(name = "scan", defaultPhase = LifecyclePhase.VERIFY)
public class VigilMojo extends AbstractMojo {

    @Parameter(defaultValue = "${project.basedir}", readonly = true, required = true)
    private File projectDir;

    @Parameter(defaultValue = "${project.build.directory}/vigil", property = "vigil.outputDir")
    private File outputDir;

    @Override
    public void execute() throws MojoExecutionException, MojoFailureException {
        try {
            Path projectPath = projectDir.toPath();
            Path outputPath = outputDir.toPath();

            getLog().info("Starting Vigil compliance scan...");
            getLog().info("Project: " + projectPath);

            // Run scan
            Vigil vigil = new Vigil();
            ReportData reportData = vigil.scan(projectPath);

            // Generate HTML report
            HtmlReportGenerator reportGenerator = new HtmlReportGenerator();
            Path reportPath = reportGenerator.generate(reportData, outputPath);

            // Print console summary
            ConsoleSummaryPrinter printer = new ConsoleSummaryPrinter();
            printer.print(reportData, reportPath);

            getLog().info("Vigil scan complete");

        } catch (Exception e) {
            getLog().error("Error during Vigil scan: " + e.getMessage(), e);
            // Don't throw exception - we don't want to fail the build
        }
    }
}
