package io.github.jody2905.logwarden.core.parse;

import io.github.jody2905.logwarden.core.Event;
import io.github.jody2905.logwarden.core.EventType;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Linux /var/log/auth.log (or /var/log/secure): sshd logins, sudo, useradd, usermod and gpasswd. */
public final class LinuxAuthParser implements LogParser {

    private static final String IP = "(?<ip>[0-9a-fA-F:.]+)";
    private static final Pattern PROGRAM = Pattern.compile("^(?<prog>[\\w.-]+)(?:\\[\\d+])?:\\s*(?<msg>.*)$");
    private static final Pattern FAILED = Pattern.compile("^Failed (?:password|publickey) for (?:invalid user )?(?<user>\\S+) from " + IP + ".*");
    private static final Pattern ACCEPTED = Pattern.compile("^Accepted (?<method>password|publickey|keyboard-interactive/pam) for (?<user>\\S+) from " + IP + ".*");
    private static final Pattern SUDO = Pattern.compile("^\\s*(?<user>\\S+) : .*?USER=(?<as>\\S+) ; COMMAND=(?<cmd>.*)$");
    private static final Pattern USERADD = Pattern.compile("^new user: name=(?<name>[^,\\s]+).*");
    private static final Pattern USERMOD = Pattern.compile("^add '(?<user>[^']+)' to (?:shadow )?group '(?<group>[^']+)'.*");
    private static final Pattern GPASSWD = Pattern.compile("^(?:user )?(?<user>\\S+) added by (?<by>\\S+) to group (?<group>\\S+).*");

    private final SyslogTime time;

    public LinuxAuthParser(SyslogTime time) {
        this.time = time;
    }

    @Override public String name() { return "linux"; }

    @Override public String description() { return "Linux auth.log / secure (sshd, sudo, useradd, usermod)"; }

    @Override
    public boolean looksLike(String line) {
        return line.matches(".*\\s(sshd|sudo|useradd|usermod|gpasswd|su|login|systemd-logind)(\\[\\d+])?:.*");
    }

    @Override
    public Optional<Event> parse(String line) {
        var parts = time.split(line);
        if (parts.isEmpty()) return Optional.empty();
        var p = parts.get();
        Matcher pm = PROGRAM.matcher(p.rest());
        if (!pm.matches()) return Optional.empty();
        String prog = pm.group("prog"), msg = pm.group("msg").strip();
        Event.Builder b;
        Matcher m;
        if (prog.equals("sshd") && (m = FAILED.matcher(msg)).matches()) {
            b = Event.at(p.time(), "linux", EventType.LOGIN_FAILURE).user(m.group("user")).srcIp(m.group("ip"))
                    .message("SSH login failed for " + m.group("user") + " from " + m.group("ip"));
        } else if (prog.equals("sshd") && (m = ACCEPTED.matcher(msg)).matches()) {
            b = Event.at(p.time(), "linux", EventType.LOGIN_SUCCESS).user(m.group("user")).srcIp(m.group("ip"))
                    .target("ssh/" + m.group("method")).message("SSH login (" + m.group("method") + ") for " + m.group("user") + " from " + m.group("ip"));
        } else if (prog.equals("sudo") && (m = SUDO.matcher(msg)).matches()) {
            b = Event.at(p.time(), "linux", EventType.PRIVILEGE_USE).user(m.group("user")).target(m.group("cmd").strip())
                    .message(m.group("user") + " ran as " + m.group("as") + ": " + m.group("cmd").strip());
        } else if (prog.equals("useradd") && (m = USERADD.matcher(msg)).matches()) {
            b = Event.at(p.time(), "linux", EventType.ACCOUNT_CREATED).target(m.group("name"))
                    .message("New account " + m.group("name"));
        } else if (prog.equals("usermod") && (m = USERMOD.matcher(msg)).matches()) {
            b = Event.at(p.time(), "linux", EventType.GROUP_MEMBER_ADDED).user(m.group("user")).target(m.group("group"))
                    .message(m.group("user") + " added to group " + m.group("group"));
        } else if (prog.equals("gpasswd") && (m = GPASSWD.matcher(msg)).matches()) {
            b = Event.at(p.time(), "linux", EventType.GROUP_MEMBER_ADDED).user(m.group("user")).target(m.group("group"))
                    .message(m.group("user") + " added to group " + m.group("group") + " by " + m.group("by"));
        } else {
            b = Event.at(p.time(), "linux", EventType.OTHER).message(prog + ": " + truncate(msg));
        }
        return Optional.of(b.host(p.host()).raw(line).build());
    }

    static String truncate(String s) {
        return s.length() > 200 ? s.substring(0, 200) + "…" : s;
    }
}
