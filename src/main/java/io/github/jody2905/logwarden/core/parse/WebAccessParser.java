package io.github.jody2905.logwarden.core.parse;

import io.github.jody2905.logwarden.core.Event;
import io.github.jody2905.logwarden.core.EventType;

import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Apache / nginx access logs in the common or combined format. */
public final class WebAccessParser implements LogParser {

    private static final Pattern LINE = Pattern.compile(
            "^(?<ip>\\S+) \\S+ (?<user>\\S+) \\[(?<time>[^]]+)] \"(?<method>[A-Z]+) (?<path>\\S+)(?: [^\"]*)?\" (?<status>\\d{3}) (?<size>\\S+)(?: \"(?<ref>[^\"]*)\" \"(?<ua>[^\"]*)\")?.*$");
    private static final DateTimeFormatter TIME = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    private final String defaultHost;

    public WebAccessParser(String defaultHost) {
        this.defaultHost = defaultHost;
    }

    @Override public String name() { return "web"; }

    @Override public String description() { return "Apache / nginx access log (common or combined format)"; }

    @Override
    public boolean looksLike(String line) {
        return LINE.matcher(line).matches();
    }

    @Override
    public Optional<Event> parse(String line) {
        Matcher m = LINE.matcher(line);
        if (!m.matches()) return Optional.empty();
        OffsetDateTime t;
        try {
            t = OffsetDateTime.parse(m.group("time"), TIME);
        } catch (RuntimeException e) {
            return Optional.empty();
        }
        String user = m.group("user").equals("-") ? null : m.group("user");
        String ua = m.group("ua");
        return Optional.of(Event.at(t.toInstant(), "web", EventType.HTTP_REQUEST)
                .host(defaultHost).user(user).srcIp(m.group("ip")).target(m.group("method") + " " + m.group("path"))
                .status(Integer.parseInt(m.group("status")))
                .message(m.group("method") + " " + LinuxAuthParser.truncate(m.group("path")) + " → " + m.group("status")
                        + (ua == null || ua.equals("-") ? "" : " (" + LinuxAuthParser.truncate(ua) + ")"))
                .raw(line).build());
    }
}
