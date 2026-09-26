package com.github.guoyyit.securitybaselinedriftjava.domain;

import java.util.Objects;

/**
 * A scope identifies which sources a rule / baseline entry / exemption applies to.
 * Specificity order (higher wins on conflict): SOURCE &gt; GROUP &gt; GLOBAL.
 */
public record Scope(Kind kind, String value) implements Comparable<Scope> {

    public enum Kind { GLOBAL, GROUP, SOURCE }

    public static final Scope GLOBAL = new Scope(Kind.GLOBAL, "*");

    public static Scope global() {
        return GLOBAL;
    }

    public static Scope group(String group) {
        Objects.requireNonNull(group, "group");
        return new Scope(Kind.GROUP, group);
    }

    public static Scope source(String sourceId) {
        Objects.requireNonNull(sourceId, "sourceId");
        return new Scope(Kind.SOURCE, sourceId);
    }

    /** Number of hierarchy levels matched; higher means more specific. */
    public int specificity() {
        return switch (kind) {
            case SOURCE -> 3;
            case GROUP -> 2;
            case GLOBAL -> 1;
        };
    }

    /**
     * @param sourceId id of the snapshot source
     * @param groups   groups the source belongs to (may be empty)
     * @return true if this scope covers the given source
     */
    public boolean matches(String sourceId, java.util.Set<String> groups) {
        return switch (kind) {
            case GLOBAL -> true;
            case GROUP -> groups != null && groups.contains(value);
            case SOURCE -> Objects.equals(value, sourceId);
        };
    }

    @Override
    public int compareTo(Scope other) {
        int c = Integer.compare(this.specificity(), other.specificity());
        if (c != 0) {
            return c;
        }
        c = this.kind.name().compareTo(other.kind.name());
        if (c != 0) {
            return c;
        }
        return this.value.compareTo(other.value);
    }

    @Override
    public String toString() {
        return kind.name().toLowerCase() + ":" + value;
    }
}
