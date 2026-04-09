package com.vigil.rules;

public enum RuleCategory {
    SECRETS("Hardcoded Secrets"),
    PII("PII Handling"),
    DEPENDENCIES("Insecure Dependencies"),
    STORAGE("Data Storage"),
    LOGGING("Logging Compliance"),
    ENCRYPTION("Encryption Standards"),
    ACCESS_CONTROL("Access Control");

    private final String displayName;

    RuleCategory(String displayName) {
        this.displayName = displayName;
    }

    public String getDisplayName() {
        return displayName;
    }
}
