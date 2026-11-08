package io.github.jody2905.logwarden.core.parse;

import io.github.jody2905.logwarden.core.Event;
import io.github.jody2905.logwarden.core.EventType;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Windows Security log events, one JSON object per line. Field names follow the event's XML data
 * (TargetUserName, IpAddress, SubjectUserName, MemberName…), as exported by PowerShell:
 * <pre>
 * Get-WinEvent -LogName Security -MaxEvents 5000 | ForEach-Object {
 *   $x = [xml]$_.ToXml(); $d = @{ TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o'); EventID = $_.Id; Computer = $_.MachineName }
 *   $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
 *   $d | ConvertTo-Json -Compress } | Set-Content security.jsonl
 * </pre>
 */
public final class WindowsEventParser implements LogParser {

    private static final Pattern CN = Pattern.compile("^CN=([^,]+).*");
    private static final Pattern DATE_MS = Pattern.compile("^/Date\\((\\d+)\\)/$");

    @Override public String name() { return "windows"; }

    @Override public String description() { return "Windows Security events as JSON lines (4624, 4625, 4720, 4728/4732/4756, 4672, 1102)"; }

    @Override
    public boolean looksLike(String line) {
        String l = line.strip();
        return l.startsWith("{") && (l.contains("\"EventID\"") || l.contains("\"Id\""));
    }

    @Override
    public Optional<Event> parse(String line) {
        if (!looksLike(line)) return Optional.empty();
        Map<String, String> d;
        try {
            d = MiniJson.object(line);
        } catch (RuntimeException e) {
            return Optional.empty();
        }
        Instant t = time(first(d, "TimeCreated", "TimeGenerated", "@timestamp"));
        String idText = first(d, "EventID", "Id");
        if (t == null || idText == null) return Optional.empty();
        int id;
        try {
            id = Integer.parseInt(idText.strip());
        } catch (NumberFormatException e) {
            return Optional.empty();
        }
        String host = first(d, "Computer", "MachineName");
        String target = clean(d.get("TargetUserName")), subject = clean(d.get("SubjectUserName"));
        String ip = clean(d.get("IpAddress"));
        String logonType = d.get("LogonType");
        Event.Builder b = switch (id) {
            case 4624 -> Event.at(t, "windows", target != null && target.endsWith("$") ? EventType.OTHER : EventType.LOGIN_SUCCESS)
                    .user(target).srcIp(ip).target(logonType == null ? null : "logon type " + logonType)
                    .message("Windows logon" + (logonType == null ? "" : " (type " + logonType + ")") + " for " + target + (ip == null ? "" : " from " + ip));
            case 4625 -> Event.at(t, "windows", EventType.LOGIN_FAILURE).user(target).srcIp(ip)
                    .message("Windows logon failed for " + target + (ip == null ? "" : " from " + ip));
            case 4720 -> Event.at(t, "windows", EventType.ACCOUNT_CREATED).user(subject).target(target)
                    .message(subject + " created account " + target);
            case 4728, 4732, 4756 -> {
                String member = member(d);
                yield Event.at(t, "windows", EventType.GROUP_MEMBER_ADDED).user(member).target(target)
                        .message(member + " added to group " + target + (subject == null ? "" : " by " + subject));
            }
            case 4672 -> Event.at(t, "windows", EventType.PRIVILEGE_USE).user(subject).target("special privileges")
                    .message("Admin privileges assigned to " + subject + "'s logon");
            case 1102 -> Event.at(t, "windows", EventType.LOG_CLEARED).user(subject)
                    .message("Security log cleared by " + subject);
            default -> Event.at(t, "windows", EventType.OTHER).user(target != null ? target : subject).message("Windows event " + id);
        };
        return Optional.of(b.host(host).raw(line.strip()).build());
    }

    private static String member(Map<String, String> d) {
        String name = clean(d.get("MemberName"));
        if (name != null) {
            Matcher m = CN.matcher(name);
            return m.matches() ? m.group(1) : name;
        }
        return clean(d.get("MemberSid"));
    }

    private static String clean(String v) {
        if (v == null) return null;
        v = v.strip();
        return v.isEmpty() || v.equals("-") ? null : v;
    }

    private static String first(Map<String, String> d, String... keys) {
        for (String k : keys) if (d.get(k) != null) return d.get(k);
        return null;
    }

    private static Instant time(String v) {
        if (v == null) return null;
        Matcher m = DATE_MS.matcher(v.strip());
        if (m.matches()) return Instant.ofEpochMilli(Long.parseLong(m.group(1)));  // ConvertTo-Json on PowerShell 5
        try {
            return OffsetDateTime.parse(v.strip()).toInstant();
        } catch (RuntimeException e) {
            try {
                return Instant.parse(v.strip());
            } catch (RuntimeException e2) {
                return null;
            }
        }
    }
}
