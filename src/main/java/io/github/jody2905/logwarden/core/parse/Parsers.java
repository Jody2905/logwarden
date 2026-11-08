package io.github.jody2905.logwarden.core.parse;

import io.github.jody2905.logwarden.core.Event;

import java.time.Clock;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** All parsers, and format detection for uploads. */
public final class Parsers {

    public record Result(List<Event> events, int lines, int skipped, Map<String, Integer> byFormat, List<String> skippedSamples) { }

    private final List<LogParser> parsers;

    public Parsers(Clock clock, ZoneId syslogZone, String webHost) {
        SyslogTime t = new SyslogTime(clock, syslogZone);
        // Order matters for auto-detection: firewall lines are also syslog lines
        parsers = List.of(new WindowsEventParser(), new FirewallParser(t), new LinuxAuthParser(t), new WebAccessParser(webHost));
    }

    public List<LogParser> all() {
        return parsers;
    }

    public Optional<LogParser> byName(String name) {
        return parsers.stream().filter(p -> p.name().equalsIgnoreCase(name)).findFirst();
    }

    /**
     * Parse a block of text. With format "auto", each line goes to the first parser that recognises it,
     * so one upload can mix formats.
     */
    public Result parse(String text, String format) {
        LogParser fixed = format == null || format.isBlank() || format.equalsIgnoreCase("auto") ? null
                : byName(format).orElseThrow(() -> new IllegalArgumentException("Unknown format: " + format + ". Use auto, " + names()));
        List<Event> out = new ArrayList<>();
        Map<String, Integer> by = new LinkedHashMap<>();
        List<String> samples = new ArrayList<>();
        int lines = 0, skipped = 0;
        for (String line : text.split("\\r?\\n")) {
            if (line.isBlank() || line.startsWith("#")) continue;
            lines++;
            Optional<Event> e = Optional.empty();
            LogParser used = null;
            if (fixed != null) {
                e = fixed.parse(line);
                used = fixed;
            } else {
                for (LogParser p : parsers) {
                    if (p.looksLike(line)) {
                        e = p.parse(line);
                        used = p;
                        if (e.isPresent()) break;
                    }
                }
            }
            if (e.isPresent()) {
                out.add(e.get());
                by.merge(used.name(), 1, Integer::sum);
            } else {
                skipped++;
                if (samples.size() < 5) samples.add(line.length() > 160 ? line.substring(0, 160) + "…" : line);
            }
        }
        return new Result(out, lines, skipped, by, samples);
    }

    public String names() {
        return String.join(", ", parsers.stream().map(LogParser::name).toList());
    }
}
