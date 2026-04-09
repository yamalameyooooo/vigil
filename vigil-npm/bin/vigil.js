#!/usr/bin/env node

const { execFileSync } = require('child_process');
const path = require('path');
const fs = require('fs');

// Check if Java is available
function checkJava() {
    try {
        execFileSync('java', ['-version'], { stdio: 'ignore' });
        return true;
    } catch (error) {
        return false;
    }
}

// Main execution
function main() {
    if (!checkJava()) {
        console.error('Error: Java is not installed or not in PATH');
        console.error('Vigil requires Java 17 or higher to run');
        console.error('Please install Java from https://adoptium.net/');
        process.exit(1);
    }

    // Parse command line arguments
    const args = process.argv.slice(2);
    let projectDir = '.';
    let outputDir = 'target/vigil';

    // Simple argument parsing
    for (let i = 0; i < args.length; i++) {
        if (args[i] === '-o' || args[i] === '--output') {
            outputDir = args[i + 1];
            i++;
        } else if (!args[i].startsWith('-')) {
            projectDir = args[i];
        }
    }

    // Find the vigil-cli JAR (assumes it's built and available)
    const jarPath = path.join(__dirname, '..', '..', 'vigil-cli', 'target', 'vigil-cli-1.0.0-SNAPSHOT.jar');

    if (!fs.existsSync(jarPath)) {
        console.error('Error: Vigil CLI JAR not found at:', jarPath);
        console.error('Please build the project first: mvn clean package');
        process.exit(1);
    }

    // Execute the Java CLI
    try {
        execFileSync(
            'java',
            ['-jar', jarPath, projectDir, '--output', outputDir],
            { stdio: 'inherit' }
        );
    } catch (error) {
        console.error('Error executing Vigil:', error.message);
        process.exit(error.status || 1);
    }
}

main();
