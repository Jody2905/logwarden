package io.github.jody2905.logwarden.core;

import java.time.Instant;

/**
 * One log line, normalised so every rule can read Linux, Windows, web and firewall logs the same way.
 *
 * @param id       database id (null until saved)
 * @param time     when it happened (UTC)
 * @param source   which kind of log it came from: linux, windows, web, firewall
 * @param host     machine that wrote the log
 * @param type     what happened
 * @param user     account involved, if any
 * @param srcIp    where it came from, if known
 * @param dstPort  port it was aimed at (firewall), if known
 * @param target   the thing acted on: a group name, a URL, a command, a new account
 * @param status   HTTP status for web logs
 * @param message  short readable summary
 * @param raw      the original line
 */
public record Event(Long id, Instant time, String source, String host, EventType type, String user, String srcIp,
                    Integer dstPort, String target, Integer status, String message, String raw) {

    public Event withId(Long newId) {
        return new Event(newId, time, source, host, type, user, srcIp, dstPort, target, status, message, raw);
    }

    public static Builder at(Instant time, String source, EventType type) {
        return new Builder(time, source, type);
    }

    /** Small builder so parsers only set the fields they know. */
    public static final class Builder {
        private final Instant time;
        private final String source;
        private final EventType type;
        private String host, user, srcIp, target, message, raw;
        private Integer dstPort, status;

        Builder(Instant time, String source, EventType type) {
            this.time = time;
            this.source = source;
            this.type = type;
        }

        public Builder host(String v) { host = v; return this; }
        public Builder user(String v) { user = v; return this; }
        public Builder srcIp(String v) { srcIp = v; return this; }
        public Builder dstPort(Integer v) { dstPort = v; return this; }
        public Builder target(String v) { target = v; return this; }
        public Builder status(Integer v) { status = v; return this; }
        public Builder message(String v) { message = v; return this; }
        public Builder raw(String v) { raw = v; return this; }

        public Event build() {
            return new Event(null, time, source, host, type, user, srcIp, dstPort, target, status, message, raw);
        }
    }
}
