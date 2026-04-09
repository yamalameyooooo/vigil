package com.vigil.dependencies;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

public class OsvClient {
    private static final String OSV_API_URL = "https://api.osv.dev/v1/query";
    private final HttpClient client;
    private final ObjectMapper mapper;

    public OsvClient() {
        this.client = HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .build();
        this.mapper = new ObjectMapper();
    }

    public List<VulnerabilityInfo> queryVulnerabilities(DependencyInfo dependency) {
        List<VulnerabilityInfo> vulnerabilities = new ArrayList<>();

        try {
            // Build request payload
            ObjectNode payload = mapper.createObjectNode();
            ObjectNode packageNode = mapper.createObjectNode();
            packageNode.put("name", dependency.artifactId());
            packageNode.put("ecosystem", dependency.ecosystem());
            payload.set("package", packageNode);
            payload.put("version", dependency.version());

            String requestBody = mapper.writeValueAsString(payload);

            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(OSV_API_URL))
                .header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .timeout(Duration.ofSeconds(10))
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

            if (response.statusCode() == 200) {
                JsonNode root = mapper.readTree(response.body());
                JsonNode vulns = root.get("vulns");

                if (vulns != null && vulns.isArray()) {
                    for (JsonNode vuln : vulns) {
                        String id = vuln.has("id") ? vuln.get("id").asText() : "UNKNOWN";
                        String summary = vuln.has("summary") ? vuln.get("summary").asText() : "No summary available";

                        // Extract severity from database_specific or severity field
                        String severity = "MEDIUM";
                        if (vuln.has("severity")) {
                            JsonNode sevNode = vuln.get("severity");
                            if (sevNode.isArray() && sevNode.size() > 0) {
                                JsonNode firstSev = sevNode.get(0);
                                if (firstSev.has("type") && firstSev.get("type").asText().equals("CVSS_V3")) {
                                    if (firstSev.has("score")) {
                                        double score = firstSev.get("score").asDouble();
                                        severity = mapCvssToSeverity(score);
                                    }
                                }
                            }
                        }

                        vulnerabilities.add(new VulnerabilityInfo(id, summary, severity));
                    }
                }
            }
        } catch (Exception e) {
            // Silently handle network/parse errors - don't block scan
        }

        return vulnerabilities;
    }

    private String mapCvssToSeverity(double cvssScore) {
        if (cvssScore >= 9.0) return "CRITICAL";
        if (cvssScore >= 7.0) return "HIGH";
        if (cvssScore >= 4.0) return "MEDIUM";
        return "LOW";
    }
}
