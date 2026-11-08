package io.github.jody2905.logwarden.core.parse;

import java.time.Clock;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Syslog timestamps. Classic lines ("Nov  7 14:02:11") have no year or time zone, so the year is taken from the
 * clock (last year if the date would be in the future) and the zone is configurable. ISO timestamps
 * ("2025-11-07T14:02:11.123+00:00", as written by rsyslog and journald) are used as they are.
 */
public final class SyslogTime {

    /** Matches either style at the start of a line, followed by the host. */
    static final Pattern PREFIX = Pattern.compile(
            "^(?:(?<classic>[A-Z][a-z]{2}\\s+\\d{1,2}\\s\\d{2}:\\d{2}:\\d{2})|(?<iso>\\d{4}-\\d{2}-\\d{2}T[\\d:.]+(?:Z|[+-]\\d{2}:?\\d{2})?))\\s+(?<host>\\S+)\\s+(?<rest>.*)$");

    private static final DateTimeFormatter CLASSIC = DateTimeFormatter.ofPattern("yyyy MMM d HH:mm:ss", Locale.ENGLISH);

    private final Clock clock;
    private final ZoneId zone;

    public SyslogTime(Clock clock, ZoneId zone) {
        this.clock = clock;
        this.zone = zone;
    }

    public record Parts(Instant time, String host, String rest) { }

    public Optional<Parts> split(String line) {
        Matcher m = PREFIX.matcher(line);
        if (!m.matches()) return Optional.empty();
        try {
            Instant t = m.group("iso") != null ? iso(m.group("iso")) : classic(m.group("classic"));
            return Optional.of(new Parts(t, m.group("host"), m.group("rest")));
        } catch (DateTimeParseException e) {
            return Optional.empty();
        }
    }

    private Instant iso(String s) {
        if (s.matches(".*([Zz]|[+-]\\d{2}:?\\d{2})$")) return OffsetDateTime.parse(s.replaceAll("([+-]\\d{2})(\\d{2})$", "$1:$2")).toInstant();
        return LocalDateTime.parse(s).atZone(zone).toInstant();
    }

    private Instant classic(String s) {
        String norm = s.replaceAll("\\s+", " ");
        int year = LocalDateTime.now(clock.withZone(zone)).getYear();
        LocalDateTime t = LocalDateTime.parse(year + " " + norm, CLASSIC);
        if (t.atZone(zone).toInstant().isAfter(clock.instant().plusSeconds(86_400))) t = t.minusYears(1);
        return t.atZone(zone).toInstant();
    }
}
