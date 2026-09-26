package com.github.guoyyit.securitybaselinedriftjava.model;

import java.util.Map;

/** A named known-good attribute set applicable to a scope; drift = diff against it. */
public record Baseline(String id, Scope scope, Map<String, String> attributes) {
}
