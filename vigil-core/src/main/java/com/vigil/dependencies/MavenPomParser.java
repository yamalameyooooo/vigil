package com.vigil.dependencies;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class MavenPomParser {
    public List<DependencyInfo> parse(Path pomPath) {
        List<DependencyInfo> dependencies = new ArrayList<>();

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document doc = builder.parse(pomPath.toFile());
            doc.getDocumentElement().normalize();

            NodeList dependencyNodes = doc.getElementsByTagName("dependency");

            for (int i = 0; i < dependencyNodes.getLength(); i++) {
                Element dependency = (Element) dependencyNodes.item(i);

                String groupId = getElementText(dependency, "groupId");
                String artifactId = getElementText(dependency, "artifactId");
                String version = getElementText(dependency, "version");

                if (groupId != null && artifactId != null && version != null) {
                    dependencies.add(new DependencyInfo(groupId, artifactId, version, "Maven"));
                }
            }
        } catch (Exception e) {
            // Silently handle parse errors
        }

        return dependencies;
    }

    private String getElementText(Element parent, String tagName) {
        NodeList nodes = parent.getElementsByTagName(tagName);
        if (nodes.getLength() > 0) {
            return nodes.item(0).getTextContent().trim();
        }
        return null;
    }
}
