package io.github.jody2905.logwarden.core;

import java.time.Instant;
import java.util.List;

/**
 * What a rule reports when it fires.
 *
 * @param ruleId      which rule
 * @param title       one-line headline, e.g. "Brute force from 203.0.113.45"
 * @param description what happened and what to check, in plain words
 * @param severity    how urgent
 * @param mitre       MITRE ATT&CK technique, e.g. "T1110.001"
 * @param entity      who or what it is about (an IP, a user); alerts for the same rule and entity are grouped
 * @param first       first event involved
 * @param last        last event involved
 * @param evidence    the events that caused it
 */
public record Detection(String ruleId, String title, String description, Severity severity, String mitre, String entity,
                        Instant first, Instant last, List<Event> evidence) {

    public Detection {
        evidence = List.copyOf(evidence);
    }
}
