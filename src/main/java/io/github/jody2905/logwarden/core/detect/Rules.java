package io.github.jody2905.logwarden.core.detect;

import io.github.jody2905.logwarden.core.Detection;
import io.github.jody2905.logwarden.core.Event;
import io.github.jody2905.logwarden.core.EventType;
import io.github.jody2905.logwarden.core.GeoLookup;
import io.github.jody2905.logwarden.core.Severity;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.DayOfWeek;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/** The built-in detection rules. */
public final class Rules {

    private Rules() { }

    /** Settings shared by the rules. */
    public record Config(ZoneId zone, int workStartHour, int workEndHour, Set<String> badIps, GeoLookup geo) {
        public static Config defaults() {
            return new Config(ZoneId.of("America/St_Vincent"), 7, 19,
                    Set.of("203.0.113.66", "203.0.113.67", "198.51.100.77", "203.0.113.200"), GeoLookup.withSampleRanges());
        }
    }

    public static List<Rule> all(Config c) {
        return List.of(new BruteForce(), new PasswordSpray(), new SuccessAfterFailures(), new ImpossibleTravel(c.geo()),
                new AddedToAdminGroup(), new AuditLogCleared(), new SuspiciousSudo(), new OffHoursAdminLogin(c),
                new PortScan(), new WebAttack(), new WebScanner(), new ThreatIntelMatch(c.badIps()), new AccountCreated());
    }

    // ------------------------------------------------------------------ helpers

    static String join(Collection<String> items, int max) {
        List<String> l = items.stream().filter(s -> s != null && !s.isBlank()).distinct().toList();
        String s = String.join(", ", l.subList(0, Math.min(max, l.size())));
        return l.size() > max ? s + " and " + (l.size() - max) + " more" : s;
    }

    static Set<String> distinct(List<Event> events, java.util.function.Function<Event, String> f) {
        return events.stream().map(f).filter(v -> v != null).collect(Collectors.toCollection(TreeSet::new));
    }

    static List<Event> tail(List<Event> events, int n) {
        return events.size() <= n ? events : events.subList(events.size() - n, events.size());
    }

    static Detection detection(Rule r, String title, String description, Severity sev, String entity, List<Event> evidence) {
        List<Event> ev = tail(evidence, 50);
        return new Detection(r.id(), title, description, sev, r.mitre(), entity, evidence.get(0).time(), evidence.get(evidence.size() - 1).time(), ev);
    }

    static final Set<String> ADMIN_GROUPS = Set.of("sudo", "wheel", "admin", "root", "administrators", "domain admins",
            "enterprise admins", "schema admins", "backup operators", "account operators");

    static boolean isAdminGroup(String g) {
        return g != null && ADMIN_GROUPS.contains(g.toLowerCase(Locale.ROOT));
    }

    // ------------------------------------------------------------------ authentication

    /** Many failed logins from one address in a short time. */
    static final class BruteForce implements Rule {
        static final int THRESHOLD = 10;
        private final SlidingWindow w = new SlidingWindow(Duration.ofMinutes(5));

        public String id() { return "brute-force"; }
        public String name() { return "Brute-force login attempts"; }
        public String description() { return THRESHOLD + "+ failed logins from one address within 5 minutes."; }
        public String mitre() { return "T1110.001"; }
        public Severity severity() { return Severity.HIGH; }
        public void reset() { w.reset(); }

        public List<Detection> onEvent(Event e) {
            if (e.type() != EventType.LOGIN_FAILURE || e.srcIp() == null) return List.of();
            List<Event> recent = w.add(e.srcIp(), e);
            if (recent.size() < THRESHOLD) return List.of();
            Set<String> users = distinct(recent, Event::user), hosts = distinct(recent, Event::host);
            return List.of(detection(this, "Brute-force logins from " + e.srcIp(),
                    recent.size() + " failed logins from " + e.srcIp() + " in 5 minutes against " + join(users, 5) + " on " + join(hosts, 3)
                            + ". Check whether any of these accounts then logged in successfully, and block the address if it isn't yours.",
                    severity(), e.srcIp(), recent));
        }
    }

    /** One address trying a few passwords across many accounts (password spraying). */
    static final class PasswordSpray implements Rule {
        static final int USERS = 6;
        private final SlidingWindow w = new SlidingWindow(Duration.ofMinutes(15));

        public String id() { return "password-spray"; }
        public String name() { return "Password spraying"; }
        public String description() { return "Failed logins for " + USERS + "+ different accounts from one address within 15 minutes."; }
        public String mitre() { return "T1110.003"; }
        public Severity severity() { return Severity.HIGH; }
        public void reset() { w.reset(); }

        public List<Detection> onEvent(Event e) {
            if (e.type() != EventType.LOGIN_FAILURE || e.srcIp() == null || e.user() == null) return List.of();
            List<Event> recent = w.add(e.srcIp(), e);
            Set<String> users = distinct(recent, Event::user);
            if (users.size() < USERS) return List.of();
            return List.of(detection(this, "Password spraying from " + e.srcIp(),
                    e.srcIp() + " tried " + users.size() + " different accounts (" + join(users, 8) + ") in 15 minutes. "
                            + "Attackers try one common password across many accounts to stay under lockout limits.",
                    severity(), e.srcIp(), recent));
        }
    }

    /** A successful login from an address that just failed many times: the brute force may have worked. */
    static final class SuccessAfterFailures implements Rule {
        static final int FAILURES = 5;
        private final SlidingWindow failures = new SlidingWindow(Duration.ofMinutes(30));

        public String id() { return "success-after-failures"; }
        public String name() { return "Login succeeded after many failures"; }
        public String description() { return "A successful login from an address with " + FAILURES + "+ failed logins in the 30 minutes before."; }
        public String mitre() { return "T1110"; }
        public Severity severity() { return Severity.CRITICAL; }
        public void reset() { failures.reset(); }

        public List<Detection> onEvent(Event e) {
            if (e.srcIp() == null) return List.of();
            if (e.type() == EventType.LOGIN_FAILURE) {
                failures.add(e.srcIp(), e);
                return List.of();
            }
            if (e.type() != EventType.LOGIN_SUCCESS) return List.of();
            List<Event> before = failures.get(e.srcIp(), e.time());
            if (before.size() < FAILURES) return List.of();
            failures.clear(e.srcIp());
            List<Event> ev = new ArrayList<>(tail(before, 30));
            ev.add(e);
            return List.of(detection(this, "Account " + e.user() + " logged in after " + before.size() + " failures from " + e.srcIp(),
                    e.user() + " logged in to " + e.host() + " from " + e.srcIp() + " right after " + before.size() + " failed attempts from the same address. "
                            + "Treat the account as compromised: disable it or reset its password, end its sessions and check what it did next.",
                    severity(), e.user() + "@" + e.srcIp(), ev));
        }
    }

    /** The same account logging in from two places too far apart to travel between. */
    static final class ImpossibleTravel implements Rule {
        static final double MAX_KMH = 900, MIN_KM = 500;
        private final GeoLookup geo;
        private final Map<String, Event> last = new HashMap<>();

        ImpossibleTravel(GeoLookup geo) {
            this.geo = geo;
        }

        public String id() { return "impossible-travel"; }
        public String name() { return "Impossible travel"; }
        public String description() { return "One account logs in from two places more than " + (int) MIN_KM + " km apart, faster than a plane could fly between them."; }
        public String mitre() { return "T1078"; }
        public Severity severity() { return Severity.HIGH; }
        public void reset() { last.clear(); }

        public List<Detection> onEvent(Event e) {
            if (e.type() != EventType.LOGIN_SUCCESS || e.user() == null || e.srcIp() == null) return List.of();
            var here = geo.find(e.srcIp());
            if (here.isEmpty()) return List.of();
            String key = e.user().toLowerCase(Locale.ROOT);
            Event prev = last.put(key, e);
            if (prev == null) return List.of();
            var there = geo.find(prev.srcIp());
            if (there.isEmpty()) return List.of();
            double km = GeoLookup.km(there.get(), here.get());
            double hours = Math.max(Duration.between(prev.time(), e.time()).toSeconds(), 60) / 3600.0;
            if (km < MIN_KM || km / hours < MAX_KMH) return List.of();
            return List.of(detection(this, "Impossible travel for " + e.user(),
                    String.format(Locale.ROOT, "%s logged in from %s (%s), then %s (%s) %s later: %,.0f km, which would need %,.0f km/h. "
                                    + "One of these logins is probably someone else using the account.",
                            e.user(), there.get().label(), prev.srcIp(), here.get().label(), e.srcIp(), human(Duration.between(prev.time(), e.time())), km, km / hours),
                    severity(), e.user(), List.of(prev, e)));
        }
    }

    static String human(Duration d) {
        long sec = Math.max(1, d.toSeconds());
        if (sec < 120) return sec + " seconds";
        long m = sec / 60;
        return m < 120 ? m + " minutes" : (m / 60) + " hours";
    }

    // ------------------------------------------------------------------ privilege

    /** Someone added to an administrators group, worse if the account is brand new. */
    static final class AddedToAdminGroup implements Rule {
        private final Map<String, Instant> created = new LinkedHashMap<>();
        private final Map<String, Event> createdEvent = new HashMap<>();

        public String id() { return "admin-group-added"; }
        public String name() { return "Added to an admin group"; }
        public String description() { return "An account is added to sudo, wheel, Administrators, Domain Admins or another admin group. Critical if the account was created in the last 24 hours."; }
        public String mitre() { return "T1098"; }
        public Severity severity() { return Severity.HIGH; }
        public void reset() { created.clear(); createdEvent.clear(); }

        public List<Detection> onEvent(Event e) {
            if (e.type() == EventType.ACCOUNT_CREATED && e.target() != null) {
                String k = e.target().toLowerCase(Locale.ROOT);
                created.put(k, e.time());
                createdEvent.put(k, e);
                if (created.size() > 5_000) created.remove(created.keySet().iterator().next());
                return List.of();
            }
            if (e.type() != EventType.GROUP_MEMBER_ADDED || !isAdminGroup(e.target()) || e.user() == null) return List.of();
            String k = e.user().toLowerCase(Locale.ROOT);
            Instant made = created.get(k);
            boolean fresh = made != null && Duration.between(made, e.time()).compareTo(Duration.ofHours(24)) <= 0;
            List<Event> ev = fresh ? List.of(createdEvent.get(k), e) : List.of(e);
            return List.of(detection(this, (fresh ? "New account " : "") + e.user() + " added to " + e.target() + " on " + e.host(),
                    e.user() + " was added to the " + e.target() + " group on " + e.host()
                            + (fresh ? ", " + human(Duration.between(made, e.time())) + " after the account was created. Attackers often create an account and make it an admin to keep access." : ". ")
                            + " Confirm there is an approved change request for this.",
                    fresh ? Severity.CRITICAL : severity(), e.user() + "→" + e.target(), ev));
        }
    }

    static final Pattern LOG_WIPE = Pattern.compile("(?i)(rm\\s+(-\\w+\\s+)*/var/log|>\\s*/var/log/|shred\\s.*?/var/log|truncate\\s.*?/var/log|history\\s+-c|journalctl\\s+--vacuum|unset\\s+HISTFILE|wevtutil\\s+cl)");

    /** Someone wiping the audit trail. */
    static final class AuditLogCleared implements Rule {
        public String id() { return "audit-log-cleared"; }
        public String name() { return "Audit log cleared"; }
        public String description() { return "The Windows Security log is cleared (event 1102), or a command deletes or empties files in /var/log or the shell history."; }
        public String mitre() { return "T1070.001"; }
        public Severity severity() { return Severity.HIGH; }
        public void reset() { }

        public List<Detection> onEvent(Event e) {
            boolean windows = e.type() == EventType.LOG_CLEARED;
            boolean linux = e.type() == EventType.PRIVILEGE_USE && e.target() != null && LOG_WIPE.matcher(e.target()).find();
            if (!windows && !linux) return List.of();
            return List.of(detection(this, "Logs cleared on " + e.host() + " by " + e.user(),
                    (windows ? "The Windows Security log on " + e.host() + " was cleared by " + e.user() + "."
                            : e.user() + " ran \"" + e.target() + "\" on " + e.host() + ".")
                            + " Clearing logs is how attackers hide what they did. Check the account's other activity and pull logs from backups or this SIEM.",
                    severity(), e.host() + "/" + e.user(), List.of(e)));
        }
    }

    private static final Map<Pattern, String> SUDO_PATTERNS = new LinkedHashMap<>();

    static {
        SUDO_PATTERNS.put(Pattern.compile("(?i)^(/usr)?/bin/(ba|z|da)?sh(\\s+-i)?\\s*$|\\bsu\\s+-?\\s*$|\\bsu\\s+root\\b"), "opened a root shell");
        SUDO_PATTERNS.put(Pattern.compile("(?i)/etc/(shadow|sudoers|gshadow)\\b|visudo"), "read or changed a password or sudo file");
        SUDO_PATTERNS.put(Pattern.compile("(?i)chmod\\s+([ugoa]*\\+s|[2467][0-7]{3})\\b"), "set a setuid/setgid bit");
        SUDO_PATTERNS.put(Pattern.compile("(?i)(curl|wget)\\s[^|;]*\\|\\s*(ba)?sh|base64\\s+(-d|--decode)|\\bnc\\s.*-e\\s|/dev/tcp/|python\\d?\\s+-c\\s"), "downloaded or decoded code and ran it");
        SUDO_PATTERNS.put(Pattern.compile("(?i)\\b(useradd|adduser|usermod\\s+-aG)\\b|passwd\\s+\\w+"), "changed accounts");
        SUDO_PATTERNS.put(Pattern.compile("(?i)crontab|/etc/cron|systemctl\\s+(enable|start)\\s|authorized_keys"), "set up something to run again later");
    }

    /** sudo used for things that usually mean privilege escalation or persistence. */
    static final class SuspiciousSudo implements Rule {
        public String id() { return "suspicious-sudo"; }
        public String name() { return "Suspicious sudo command"; }
        public String description() { return "sudo used to open a root shell, touch /etc/shadow or sudoers, set setuid bits, pipe a download into a shell, change accounts or add persistence."; }
        public String mitre() { return "T1548.003"; }
        public Severity severity() { return Severity.MEDIUM; }
        public void reset() { }

        public List<Detection> onEvent(Event e) {
            if (e.type() != EventType.PRIVILEGE_USE || !"linux".equals(e.source()) || e.target() == null) return List.of();
            if (LOG_WIPE.matcher(e.target()).find()) return List.of(); // the log-cleared rule covers this
            for (var p : SUDO_PATTERNS.entrySet()) {
                if (p.getKey().matcher(e.target()).find()) {
                    boolean high = p.getValue().startsWith("downloaded") || p.getValue().startsWith("set a setuid") || p.getValue().contains("password");
                    return List.of(detection(this, e.user() + " " + p.getValue() + " with sudo on " + e.host(),
                            e.user() + " ran \"" + e.target() + "\" as root on " + e.host() + ", which " + p.getValue() + ". Check this was planned work.",
                            high ? Severity.HIGH : severity(), e.host() + "/" + e.user() + "/" + p.getValue(), List.of(e)));
                }
            }
            return List.of();
        }
    }

    /** Admin accounts logging in remotely outside working hours. */
    static final class OffHoursAdminLogin implements Rule {
        private final Config c;
        private final Set<String> admins = new HashSet<>(Set.of("root", "administrator", "admin"));
        private final Map<String, Event> pending = new HashMap<>();

        OffHoursAdminLogin(Config c) {
            this.c = c;
        }

        public String id() { return "off-hours-admin"; }
        public String name() { return "Admin login outside working hours"; }
        public String description() { return "A remote login by an admin account (root, Administrator, or anyone seen using admin rights or added to an admin group) on a weekend or outside " + c.workStartHour() + ":00–" + c.workEndHour() + ":00 local time."; }
        public String mitre() { return "T1078.003"; }
        public Severity severity() { return Severity.MEDIUM; }
        public void reset() { admins.retainAll(Set.of("root", "administrator", "admin")); pending.clear(); }

        public List<Detection> onEvent(Event e) {
            String u = e.user() == null ? null : e.user().toLowerCase(Locale.ROOT);
            if (u != null && (e.type() == EventType.PRIVILEGE_USE || (e.type() == EventType.GROUP_MEMBER_ADDED && isAdminGroup(e.target())))) {
                admins.add(u);
                // Windows logs the admin-rights event (4672) just after the logon (4624): check a logon we held back
                Event held = pending.remove(u);
                if (held != null && e.type() == EventType.PRIVILEGE_USE && Duration.between(held.time(), e.time()).toSeconds() <= 120) {
                    return List.of(alert(held, e));
                }
                return List.of();
            }
            if (e.type() != EventType.LOGIN_SUCCESS || u == null || e.srcIp() == null || !offHours(e)) return List.of();
            if (!admins.contains(u)) {
                pending.put(u, e);
                if (pending.size() > 10_000) pending.clear();
                return List.of();
            }
            return List.of(alert(e, null));
        }

        private boolean offHours(Event e) {
            ZonedDateTime t = e.time().atZone(c.zone());
            boolean weekend = t.getDayOfWeek() == DayOfWeek.SATURDAY || t.getDayOfWeek() == DayOfWeek.SUNDAY;
            return weekend || t.getHour() < c.workStartHour() || t.getHour() >= c.workEndHour();
        }

        private Detection alert(Event e, Event privilege) {
            ZonedDateTime t = e.time().atZone(c.zone());
            boolean weekend = t.getDayOfWeek() == DayOfWeek.SATURDAY || t.getDayOfWeek() == DayOfWeek.SUNDAY;
            return detection(this, "Admin " + e.user() + " logged in " + (weekend ? "at the weekend" : "at night") + " from " + e.srcIp(),
                    String.format(Locale.ROOT, "%s, an admin account, logged in to %s from %s at %02d:%02d on a %s (%s time). Confirm with them that this was them.",
                            e.user(), e.host(), e.srcIp(), t.getHour(), t.getMinute(),
                            t.getDayOfWeek().getDisplayName(java.time.format.TextStyle.FULL, Locale.ENGLISH), c.zone()),
                    GeoLookup.isPrivate(e.srcIp()) ? Severity.LOW : severity(), e.user(), privilege == null ? List.of(e) : List.of(e, privilege));
        }
    }

    /** Admins seen so far (shared with the UI via the off-hours rule). */
    public static Set<String> knownAdmins(List<Rule> rules) {
        for (Rule r : rules) if (r instanceof OffHoursAdminLogin o) return Set.copyOf(o.admins);
        return Set.of();
    }

    // ------------------------------------------------------------------ network and web

    /** One address hitting many ports. */
    static final class PortScan implements Rule {
        static final int PORTS = 15;
        private final SlidingWindow w = new SlidingWindow(Duration.ofMinutes(2));

        public String id() { return "port-scan"; }
        public String name() { return "Port scan"; }
        public String description() { return "Blocked connections from one address to " + PORTS + "+ different ports within 2 minutes."; }
        public String mitre() { return "T1046"; }
        public Severity severity() { return Severity.MEDIUM; }
        public void reset() { w.reset(); }

        public List<Detection> onEvent(Event e) {
            if (e.type() != EventType.CONNECTION_BLOCKED || e.srcIp() == null || e.dstPort() == null) return List.of();
            List<Event> recent = w.add(e.srcIp(), e);
            Set<Integer> ports = recent.stream().map(Event::dstPort).collect(Collectors.toCollection(TreeSet::new));
            if (ports.size() < PORTS) return List.of();
            Set<String> targets = distinct(recent, Event::target);
            return List.of(detection(this, "Port scan from " + e.srcIp(),
                    e.srcIp() + " probed " + ports.size() + " ports (" + join(ports.stream().map(String::valueOf).toList(), 12) + ") on "
                            + join(targets, 3) + " in 2 minutes. Scans usually come before an attack: watch this address and make sure only the ports you need are open.",
                    severity(), e.srcIp(), recent));
        }
    }

    private static final Map<String, Pattern> WEB_ATTACKS = new LinkedHashMap<>();

    static {
        WEB_ATTACKS.put("SQL injection", Pattern.compile("(?i)(union(\\s|\\+|/\\*.*?\\*/)+(all(\\s|\\+)+)?select|'\\s*(or|and)\\s*'?\\d+'?\\s*=\\s*'?\\d|sleep\\(\\d|benchmark\\(|information_schema|;\\s*drop\\s+table|\\bxp_cmdshell)"));
        WEB_ATTACKS.put("cross-site scripting", Pattern.compile("(?i)(<script|javascript:|onerror\\s*=|onload\\s*=|<svg[^>]*on\\w+=|document\\.cookie)"));
        WEB_ATTACKS.put("path traversal", Pattern.compile("(?i)(\\.\\./|\\.\\.\\\\|/etc/passwd|/etc/shadow|c:\\\\windows\\\\win\\.ini|boot\\.ini)"));
        WEB_ATTACKS.put("command injection", Pattern.compile("(?i)([;|`]\\s*(cat|id|whoami|uname|wget|curl|nc|bash|sh)\\b|\\$\\((id|whoami|cat)|cmd\\.exe|powershell)"));
        WEB_ATTACKS.put("Log4Shell", Pattern.compile("(?i)\\$\\{(jndi|\\$\\{lower|\\$\\{::-j)"));
        WEB_ATTACKS.put("secret file probe", Pattern.compile("(?i)(/\\.env\\b|/\\.git/|/wp-config\\.php|/\\.aws/credentials|/id_rsa\\b|/\\.htpasswd|/server-status)"));
    }

    /** Web requests carrying attack payloads. */
    static final class WebAttack implements Rule {
        public String id() { return "web-attack"; }
        public String name() { return "Web attack payload"; }
        public String description() { return "A web request containing SQL injection, cross-site scripting, path traversal, command injection, Log4Shell, or a probe for secret files. High if the server answered 200."; }
        public String mitre() { return "T1190"; }
        public Severity severity() { return Severity.MEDIUM; }
        public void reset() { }

        public List<Detection> onEvent(Event e) {
            if (e.type() != EventType.HTTP_REQUEST || e.target() == null) return List.of();
            String url = decode(decode(e.target()));
            for (var a : WEB_ATTACKS.entrySet()) {
                if (a.getValue().matcher(url).find()) {
                    boolean ok = e.status() != null && e.status() >= 200 && e.status() < 300;
                    return List.of(detection(this, a.getKey() + " attempt from " + e.srcIp(),
                            e.srcIp() + " sent a request that looks like " + a.getKey() + ": " + LinuxAuthParserTrim.trim(url) + ". The server answered " + e.status()
                                    + (ok ? ", so the attack may have worked: check the application logs and the data it touches." : ", so it was probably refused."),
                            ok ? Severity.HIGH : severity(), e.srcIp() + "/" + a.getKey(), List.of(e)));
                }
            }
            return List.of();
        }
    }

    static String decode(String s) {
        try {
            return URLDecoder.decode(s.replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return s;
        }
    }

    /** Lots of not-found or forbidden answers to one address: a vulnerability scanner or directory brute force. */
    static final class WebScanner implements Rule {
        static final int ERRORS = 30;
        private final SlidingWindow w = new SlidingWindow(Duration.ofMinutes(2));

        public String id() { return "web-scanner"; }
        public String name() { return "Web vulnerability scan"; }
        public String description() { return ERRORS + "+ not-found or forbidden responses to one address within 2 minutes."; }
        public String mitre() { return "T1595.003"; }
        public Severity severity() { return Severity.MEDIUM; }
        public void reset() { w.reset(); }

        public List<Detection> onEvent(Event e) {
            if (e.type() != EventType.HTTP_REQUEST || e.srcIp() == null || e.status() == null) return List.of();
            if (e.status() != 404 && e.status() != 403 && e.status() != 401) return List.of();
            List<Event> recent = w.add(e.srcIp(), e);
            if (recent.size() < ERRORS) return List.of();
            return List.of(detection(this, "Web scan from " + e.srcIp(),
                    e.srcIp() + " got " + recent.size() + " not-found or forbidden responses in 2 minutes, for paths like "
                            + join(recent.stream().map(Event::target).toList(), 5) + ". That is how scanners look for hidden pages and known weaknesses.",
                    severity(), e.srcIp(), recent));
        }
    }

    /** Traffic from an address on the threat-intelligence block list. */
    static final class ThreatIntelMatch implements Rule {
        private final Set<String> bad;

        ThreatIntelMatch(Set<String> bad) {
            this.bad = bad;
        }

        public String id() { return "threat-intel"; }
        public String name() { return "Known bad address"; }
        public String description() { return "Any activity from an address on the threat-intelligence list (" + bad.size() + " addresses). High if it got in: a login, an allowed connection or a 2xx web response."; }
        public String mitre() { return "T1071"; }
        public Severity severity() { return Severity.MEDIUM; }
        public void reset() { }

        public List<Detection> onEvent(Event e) {
            if (e.srcIp() == null || !bad.contains(e.srcIp())) return List.of();
            boolean got = e.type() == EventType.LOGIN_SUCCESS || e.type() == EventType.CONNECTION_ALLOWED
                    || (e.type() == EventType.HTTP_REQUEST && e.status() != null && e.status() < 300);
            return List.of(detection(this, "Activity from known bad address " + e.srcIp(),
                    e.srcIp() + " is on the threat-intelligence list. " + e.message() + "."
                            + (got ? " It got through, so check what it reached." : " It was refused or failed."),
                    got ? Severity.HIGH : severity(), e.srcIp(), List.of(e)));
        }
    }

    /** Every new account, for the record. */
    static final class AccountCreated implements Rule {
        public String id() { return "account-created"; }
        public String name() { return "New account created"; }
        public String description() { return "A new user account appears on a Linux server or in Windows. Low on its own: check it matches a joiner request."; }
        public String mitre() { return "T1136"; }
        public Severity severity() { return Severity.LOW; }
        public void reset() { }

        public List<Detection> onEvent(Event e) {
            if (e.type() != EventType.ACCOUNT_CREATED || e.target() == null) return List.of();
            return List.of(detection(this, "New account " + e.target() + " on " + e.host(),
                    "Account " + e.target() + " was created on " + e.host() + (e.user() == null ? "" : " by " + e.user()) + ". Check it matches an approved request.",
                    severity(), e.host() + "/" + e.target(), List.of(e)));
        }
    }

    /** Keeps payloads readable in descriptions. */
    static final class LinuxAuthParserTrim {
        static String trim(String s) {
            return s.length() > 160 ? s.substring(0, 160) + "…" : s;
        }
    }
}
