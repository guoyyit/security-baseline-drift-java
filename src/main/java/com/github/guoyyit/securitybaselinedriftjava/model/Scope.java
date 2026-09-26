package com.github.guoyyit.securitybaselinedriftjava.model;

import java.util.regex.Pattern;

/**
 * Applicability scope of a rule / baseline / exemption.
 * Specificity order (highest wins on conflict): EXACT > REGEX > PREFIX > GLOBAL.
 */
public record Scope(Kind kind, String pattern) {

    public enum Kind { GLOBAL, PREFIX, EXACT, REGEX }

    public static Scope global() { return new Scope(Kind.GLOBAL, "*"); }
    public static Scope exact(String sourceId) { return new Scope(Kind.EXACT, sourceId); }
    public static Scope prefix(String prefix) { return new Scope(Kind.PREFIX, prefix); }
    public static Scope regex(String regex) { return new Scope(Kind.REGEX, regex); }

    public boolean matches(String sourceId) {
        return switch (kind) {
            case GLOBAL -> true;
            case EXACT -> pattern.equals(sourceId);
            case PREFIX -> sourceId != null && sourceId.startsWith(pattern);
            case REGEX -> sourceId != null && Pattern.matches(pattern, sourceId);
        };
    }

    /** Higher means more specific. */
    public int specificity() {
        return switch (kind) {
            case EXACT -> 4;
            case REGEX -> 3;
            case PREFIX -> 2;
            case GLOBAL -> 1;
        };
    }
}
