package io.github.jody2905.logwarden.core.parse;

import io.github.jody2905.logwarden.core.Event;
import io.github.jody2905.logwarden.core.EventType;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Linux firewall logs from UFW or iptables LOG rules (kernel lines with SRC= DST= DPT=). */
public final class FirewallParser implements LogParser {

    private static final Pattern KV = Pattern.compile("\\b([A-Z]+)=(\\S*)");
    private static final Pattern ACTION = Pattern.compile("\\[UFW (BLOCK|ALLOW|AUDIT|LIMIT BLOCK)]|\\b(DROP|REJECT|ACCEPT|BLOCK|DENY)\\b");

    private final SyslogTime time;

    public FirewallParser(SyslogTime time) {
        this.time = time;
    }

    @Override public String name() { return "firewall"; }

    @Override public String description() { return "UFW / iptables firewall log (kernel lines with SRC= DST= DPT=)"; }

    @Override
    public boolean looksLike(String line) {
        return line.contains(" SRC=") && line.contains(" DST=");
    }

    @Override
    public Optional<Event> parse(String line) {
        if (!looksLike(line)) return Optional.empty();
        var parts = time.split(line);
        if (parts.isEmpty()) return Optional.empty();
        var p = parts.get();
        Map<String, String> kv = new HashMap<>();
        Matcher m = KV.matcher(p.rest());
        while (m.find()) kv.putIfAbsent(m.group(1), m.group(2));
        Matcher a = ACTION.matcher(p.rest());
        String action = a.find() ? (a.group(1) != null ? a.group(1) : a.group(2)) : "BLOCK";
        boolean blocked = !(action.equals("ALLOW") || action.equals("ACCEPT") || action.equals("AUDIT"));
        Integer port = null;
        try {
            if (kv.get("DPT") != null) port = Integer.valueOf(kv.get("DPT"));
        } catch (NumberFormatException ignored) {
            // leave unknown
        }
        String proto = kv.getOrDefault("PROTO", "?");
        return Optional.of(Event.at(p.time(), "firewall", blocked ? EventType.CONNECTION_BLOCKED : EventType.CONNECTION_ALLOWED)
                .host(p.host()).srcIp(kv.get("SRC")).dstPort(port).target(kv.get("DST"))
                .message((blocked ? "Blocked " : "Allowed ") + proto + " " + kv.get("SRC") + " → " + kv.get("DST") + (port == null ? "" : ":" + port))
                .raw(line).build());
    }
}
