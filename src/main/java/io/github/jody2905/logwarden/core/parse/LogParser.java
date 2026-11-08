package io.github.jody2905.logwarden.core.parse;

import io.github.jody2905.logwarden.core.Event;

import java.util.Optional;

/** Reads one kind of log line into an {@link Event}. */
public interface LogParser {

    /** Short name used in the API and the UI, e.g. "linux". */
    String name();

    /** Human description, e.g. "Linux auth.log (sshd, sudo, useradd)". */
    String description();

    /** Quick check used to guess the format of an upload. */
    boolean looksLike(String line);

    /** The event for this line, or empty if the line isn't one this parser understands. */
    Optional<Event> parse(String line);
}
