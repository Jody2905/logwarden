# LogWarden

**A small SIEM for small IT teams.** LogWarden collects Linux, Windows, web server and firewall logs, runs thirteen detection rules mapped to MITRE ATT&CK, groups what it finds into alerts, and gives analysts a place to investigate and record what they did.

Built with Java 17, Spring Boot 4, Spring Security, Spring Data JPA, Flyway and PostgreSQL.

**[Live demo](https://logwarden-k2df.onrender.com)**: sign in as `analyst` / `logwarden-demo`.

![Overview](docs/overview.png)

## What it does

- **Reads real log formats**: Linux `auth.log` (sshd, sudo, useradd, usermod), Windows Security events exported as JSON, Apache/nginx access logs, and UFW/iptables firewall logs. One upload can mix formats; LogWarden works out each line.
- **Detects attacks** with thirteen rules, each explained in plain words and linked to its ATT&CK technique.
- **Groups repeats**: a 500-guess brute force is one alert that keeps counting, not 500.
- **Runs the alert workflow**: New → Investigating → Resolved or False positive, with assignment and an investigation trail recording every note and status change.
- **Lets you dig in**: every alert keeps its evidence (the original log lines), and you can search all events by text, type, source, IP address, user or host.
- **Watches itself**: sign-ins to LogWarden are logged as events too, so its own brute-force rule catches someone guessing passwords at it, and the address is locked out after 10 failures.

## Detection rules

| Rule | Looks for | ATT&CK |
|---|---|---|
| Brute-force login attempts | 10+ failed logins from one address within 5 minutes | T1110.001 |
| Password spraying | Failed logins for 6+ different accounts from one address within 15 minutes | T1110.003 |
| Login succeeded after many failures | A successful login from an address with 5+ failures in the 30 minutes before (critical) | T1110 |
| Impossible travel | One account logging in from two places 500+ km apart, faster than a plane could fly | T1078 |
| Added to an admin group | An account added to sudo, wheel, Administrators, Domain Admins…; critical if the account is under 24 hours old | T1098 |
| Audit log cleared | Windows event 1102, or commands that delete or empty `/var/log` or shell history | T1070.001 |
| Suspicious sudo command | Root shells, reading `/etc/shadow`, setuid bits, piping a download into a shell, persistence | T1548.003 |
| Admin login outside working hours | A remote login by an admin account at night or at the weekend (local time) | T1078.003 |
| Port scan | Blocked connections to 15+ ports from one address within 2 minutes | T1046 |
| Web attack payload | SQL injection, cross-site scripting, path traversal, command injection, Log4Shell, secret-file probes; high if the server answered 200 | T1190 |
| Web vulnerability scan | 30+ not-found or forbidden responses to one address within 2 minutes | T1595.003 |
| Known bad address | Any activity from an address on the threat-intelligence list | T1071 |
| New account created | A new account on a server or in Windows | T1136 |

## How well it works

LogWarden includes an attack simulator that writes a realistic working day for a small office (four servers, twenty staff) in the real log formats: staff logons and typos, admin work, 2,200 website visits, and the internet's usual SSH bots and port probes. Hidden in it are nine attacks, including a full break-in:

> An attacker guesses the `deploy` account's password from São Paulo, opens a root shell with sudo, reads `/etc/shadow`, creates a backdoor account `svc-backup`, makes it an admin 15 seconds later, downloads and runs a script, then shreds the auth log.

On that day (3,128 log lines) LogWarden raises **22 alerts, one for every step of every attack, and no false alarms**. Impossible travel spots the São Paulo login on its own as well. This is checked by the test suite on every build.

![An alert](docs/alert.png)

## Try it

**Online:** https://logwarden-k2df.onrender.com. Sign in as `analyst` / `logwarden-demo`. It runs on Render's free plan, so the first visit takes about a minute to wake it.

**On your computer** (Java 17 or newer):

```bash
./mvnw spring-boot:run          # Windows: mvnw.cmd spring-boot:run
```

Open http://localhost:8080 and sign in as `analyst` / `logwarden-demo` (or `admin` / `logwarden-admin`). It starts with an in-memory database and the simulated day already loaded.

## Sending logs

Upload files or paste lines on the **Add logs** page, or send them from your servers with an API key:

```bash
curl -X POST "https://your-logwarden/api/ingest?format=linux" \
  -H "X-API-Key: $LOGWARDEN_API_KEY" \
  --data-binary @/var/log/auth.log
```

Formats: `auto` (the default), `linux`, `windows`, `web`, `firewall`. The API key can only send logs; it can't read anything.

Windows Security events can be exported as JSON lines with PowerShell (run as administrator):

```powershell
Get-WinEvent -LogName Security -MaxEvents 5000 | ForEach-Object {
  $x = [xml]$_.ToXml()
  $d = @{ TimeCreated = $_.TimeCreated.ToUniversalTime().ToString('o'); EventID = $_.Id; Computer = $_.MachineName }
  $x.Event.EventData.Data | ForEach-Object { $d[$_.Name] = $_.'#text' }
  $d | ConvertTo-Json -Compress
} | Set-Content security.jsonl
```

Send older logs first: the rules read events in time order.

## Security

- Two roles: **analyst** (read everything, work alerts, add logs) and **admin** (also switch rules on and off, reset the demo).
- Passwords are stored as bcrypt hashes; 10 failed sign-ins from one address lock it out for 15 minutes.
- The browser session uses CSRF protection; log shippers use an API key compared in constant time.
- A strict Content Security Policy (no inline scripts or styles), and every value from a log is escaped before it is shown, because logs contain attackers' own text.
- Events are deleted after 30 days (`logwarden.retention-days`); alerts keep their summary.

## Configuration

| Environment variable | What it sets | Default |
|---|---|---|
| `DATABASE_URL` | PostgreSQL connection string, e.g. from Neon (`postgresql://user:pass@host/db?sslmode=require`) | in-memory H2 |
| `LOGWARDEN_ADMIN_PASSWORD` | Password for `admin` | `logwarden-admin` |
| `LOGWARDEN_ANALYST_PASSWORD` | Password for `analyst` | `logwarden-demo` |
| `LOGWARDEN_API_KEY` | Key for log shippers (blank turns API-key sending off) | blank |
| `LOGWARDEN_DEMO_DATA` | Load the simulated day when the database is empty | `true` |

Working hours, time zone, the threat-intelligence list and thresholds are in `src/main/resources/application.properties`.

## Deploying

The repository includes a `Dockerfile` and a Render Blueprint (`render.yaml`). In Render choose **New → Blueprint**, pick this repository, and fill in `DATABASE_URL` (a Neon PostgreSQL connection string) and `LOGWARDEN_ADMIN_PASSWORD`. Flyway creates the tables on the first start.

## Project layout

```
src/main/java/io/github/jody2905/logwarden/
  core/            plain Java, no framework
    parse/         one parser per log format
    detect/        the rules, sliding windows, and the engine that groups repeats
    sim/           the attack simulator
    GeoLookup      address → place, for impossible travel
  domain/          JPA entities and repositories
  service/         ingest, alerts, overview figures, start-up and housekeeping, self-audit
  web/             REST API
  config/          Spring Security, settings, sign-in lockout
src/main/resources/
  db/migration/    Flyway schema (works on PostgreSQL and H2)
  static/          the dashboard: plain HTML, CSS and JavaScript
```

The detection core has no Spring dependencies, so it can be tested on its own and reused.

## Tests

```bash
./mvnw verify
```

22 tests: the parsers on real log lines; each rule's thresholds and the things it must ignore (a typo or two from the office, a trip to Barbados, routine sudo); the full simulated day (every attack found, nothing else); and the web app end to end (sign-in, roles, CSRF, the API key, the alert workflow, and LogWarden catching a brute force against itself). GitHub Actions runs them on every push.

## Note

All people, hosts and addresses in the simulator are invented. Public addresses come from the ranges reserved for documentation (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), and the place for each is made up for the demo.

## License

MIT
