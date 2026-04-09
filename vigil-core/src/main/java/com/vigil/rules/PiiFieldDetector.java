package com.vigil.rules;

import com.vigil.rules.Severity;

import java.util.regex.Pattern;

public class PiiFieldDetector {

    private static final Pattern PII_PATTERN = Pattern.compile(
        ".*(email|phone|ssn|social[_-]?security|address|dob|date[_-]?of[_-]?birth|" +
        "first[_-]?name|last[_-]?name|full[_-]?name|credit[_-]?card|card[_-]?number|" +
        "cvv|passport|driver[_-]?license|medical[_-]?record|health[_-]?record|" +
        "bank[_-]?account|routing[_-]?number|tax[_-]?id|national[_-]?id).*",
        Pattern.CASE_INSENSITIVE
    );

    private static final Pattern CRITICAL_PII_PATTERN = Pattern.compile(
        ".*(ssn|social[_-]?security|credit[_-]?card|card[_-]?number|cvv|" +
        "medical[_-]?record|health[_-]?record|passport|tax[_-]?id).*",
        Pattern.CASE_INSENSITIVE
    );

    public static boolean isPiiName(String name) {
        return PII_PATTERN.matcher(name).matches();
    }

    public static boolean isCriticalPii(String name) {
        return CRITICAL_PII_PATTERN.matcher(name).matches();
    }

    public static Severity getSeverity(String name) {
        return isCriticalPii(name) ? Severity.CRITICAL : Severity.HIGH;
    }
}
