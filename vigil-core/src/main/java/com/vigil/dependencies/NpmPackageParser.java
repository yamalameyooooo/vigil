package com.vigil.dependencies;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

public class NpmPackageParser {
    private final ObjectMapper mapper = new ObjectMapper();

    public List<DependencyInfo> parse(Path packageJsonPath) {
        List<DependencyInfo> dependencies = new ArrayList<>();

        try {
            String content = Files.readString(packageJsonPath);
            JsonNode root = mapper.readTree(content);

            // Parse dependencies
            JsonNode deps = root.get("dependencies");
            if (deps != null && deps.isObject()) {
                parseDependencies(deps, dependencies);
            }

            // Parse devDependencies
            JsonNode devDeps = root.get("devDependencies");
            if (devDeps != null && devDeps.isObject()) {
                parseDependencies(devDeps, dependencies);
            }
        } catch (Exception e) {
            // Silently handle parse errors
        }

        return dependencies;
    }

    private void parseDependencies(JsonNode deps, List<DependencyInfo> dependencies) {
        Iterator<Map.Entry<String, JsonNode>> fields = deps.fields();
        while (fields.hasNext()) {
            Map.Entry<String, JsonNode> entry = fields.next();
            String name = entry.getKey();
            String version = entry.getValue().asText();

            // Strip version prefixes
            version = version.replaceFirst("^[~^>=<]+", "");

            dependencies.add(new DependencyInfo("npm", name, version, "npm"));
        }
    }
}
