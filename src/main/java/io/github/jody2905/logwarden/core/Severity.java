package io.github.jody2905.logwarden.core;

public enum Severity {
    LOW, MEDIUM, HIGH, CRITICAL;

    public Severity atLeast(Severity other) {
        return compareTo(other) >= 0 ? this : other;
    }
}
