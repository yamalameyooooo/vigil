package com.vigil.rules;

public enum Framework {
    SOC2("SOC 2"),
    GDPR("GDPR"),
    HIPAA("HIPAA"),
    PCI_DSS("PCI DSS"),
    ISO_27001("ISO 27001"),
    CCPA("CCPA"),
    LGPD("LGPD"),
    POPIA("POPIA"),
    PIPEDA("PIPEDA"),
    PDPA("PDPA");

    private final String displayName;

    Framework(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
