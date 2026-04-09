package com.vigil.rules;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class RuleRegistry {
    private final List<Rule> rules = new ArrayList<>();

    public void register(Rule rule) {
        rules.add(rule);
    }

    public List<Rule> getAllRules() {
        return Collections.unmodifiableList(rules);
    }
}
