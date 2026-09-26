package com.github.guoyyit.securitybaselinedriftjava.model;

/** Comparison operator used by a rule against a snapshot attribute. */
public enum Operator {
    EQUALS,
    NOT_EQUALS,
    REGEX_MATCHES,
    EXISTS,
    NOT_EXISTS
}
