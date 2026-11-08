package io.github.jody2905.logwarden.core;

import io.github.jody2905.logwarden.core.detect.DetectionEngine;
import io.github.jody2905.logwarden.core.detect.Rules;
import io.github.jody2905.logwarden.core.parse.Parsers;
import io.github.jody2905.logwarden.core.sim.AttackSimulator;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DetectionTest {

    static final ZoneId ZONE = ZoneId.of("America/St_Vincent");
    static final Instant T0 = Instant.parse("2025-11-06T15:00:00Z");  // a Thursday, 11:00 local

    DetectionEngine engine = new DetectionEngine(Rules.all(Rules.Config.defaults()), Duration.ofMinutes(30));

    static Event ev(int secs, EventType type, String user, String ip) {
        return Event.at(T0.plusSeconds(secs), "linux", type).host("web01").user(user).srcIp(ip).message(type + " " + user).build();
    }

    List<String> fired(List<Event> events) {
        return engine.process(events).stream().filter(o -> !o.repeat()).map(o -> o.detection().ruleId()).toList();
    }

    @Test
    void bruteForceNeedsTenFailuresInFiveMinutes() {
        List<Event> nine = new ArrayList<>();
        for (int i = 0; i < 9; i++) nine.add(ev(i * 10, EventType.LOGIN_FAILURE, "root", "203.0.113.9"));
        assertThat(fired(nine)).doesNotContain("brute-force");
        assertThat(fired(List.of(ev(95, EventType.LOGIN_FAILURE, "root", "203.0.113.9")))).contains("brute-force");
    }

    @Test
    void slowFailuresAreNotBruteForce() {
        List<Event> slow = new ArrayList<>();
        for (int i = 0; i < 20; i++) slow.add(ev(i * 120, EventType.LOGIN_FAILURE, "root", "203.0.113.9"));  // one every 2 minutes
        assertThat(fired(slow)).doesNotContain("brute-force");
    }

    @Test
    void repeatsAreGroupedIntoOneAlert() {
        List<Event> many = new ArrayList<>();
        for (int i = 0; i < 60; i++) many.add(ev(i * 3, EventType.LOGIN_FAILURE, "root", "203.0.113.9"));
        var out = engine.process(many).stream().filter(o -> o.detection().ruleId().equals("brute-force")).toList();
        assertThat(out).hasSizeGreaterThan(1);
        assertThat(out.stream().filter(o -> !o.repeat())).hasSize(1);
    }

    @Test
    void successAfterFailuresIsCritical() {
        List<Event> e = new ArrayList<>();
        for (int i = 0; i < 6; i++) e.add(ev(i * 5, EventType.LOGIN_FAILURE, "deploy", "198.51.100.140"));
        e.add(ev(60, EventType.LOGIN_SUCCESS, "deploy", "198.51.100.140"));
        var d = engine.process(e).stream().filter(o -> o.detection().ruleId().equals("success-after-failures")).findFirst().orElseThrow().detection();
        assertThat(d.severity()).isEqualTo(Severity.CRITICAL);
        assertThat(d.evidence()).hasSize(7);
        // A typo or two from the office is normal
        assertThat(fired(List.of(ev(900, EventType.LOGIN_FAILURE, "kjohn", "10.10.1.21"), ev(910, EventType.LOGIN_SUCCESS, "kjohn", "10.10.1.21"))))
                .doesNotContain("success-after-failures");
    }

    @Test
    void impossibleTravelButNotANearbyTrip() {
        // Kingstown to Bridgetown (~180 km) in 30 minutes is fine: under the 500 km floor
        assertThat(fired(List.of(ev(0, EventType.LOGIN_SUCCESS, "kjohn", "192.0.2.10"), ev(1800, EventType.LOGIN_SUCCESS, "kjohn", "192.0.2.70"))))
                .doesNotContain("impossible-travel");
        // …then Beijing 20 minutes later is not
        assertThat(fired(List.of(ev(3000, EventType.LOGIN_SUCCESS, "kjohn", "203.0.113.80")))).contains("impossible-travel");
    }

    @Test
    void webAttackDecodesTheUrlAndRatesBySuccess() {
        Event sqli = Event.at(T0, "web", EventType.HTTP_REQUEST).srcIp("198.51.100.200").status(200)
                .target("GET /services?id=1%27%20OR%20%271%27%3D%271").message("x").build();
        Event refused = Event.at(T0, "web", EventType.HTTP_REQUEST).srcIp("198.51.100.201").status(403)
                .target("GET /../../etc/passwd").message("x").build();
        Event normal = Event.at(T0, "web", EventType.HTTP_REQUEST).srcIp("192.0.2.4").status(200)
                .target("GET /search?q=vehicle+licence&page=2").message("x").build();
        var out = engine.process(List.of(sqli, refused, normal));
        assertThat(out).extracting(o -> o.detection().severity()).containsExactly(Severity.HIGH, Severity.MEDIUM);
        assertThat(out.get(0).detection().title()).startsWith("SQL injection");
        assertThat(out.get(1).detection().title()).startsWith("path traversal");
    }

    @Test
    void routineSudoIsQuietButARootShellIsNot() {
        Event routine = Event.at(T0, "linux", EventType.PRIVILEGE_USE).host("web01").user("mbrowne").target("/usr/bin/tail -n 200 /var/log/nginx/error.log").message("x").build();
        Event shell = Event.at(T0.plusSeconds(5), "linux", EventType.PRIVILEGE_USE).host("web01").user("mbrowne").target("/bin/bash").message("x").build();
        Event wipe = Event.at(T0.plusSeconds(9), "linux", EventType.PRIVILEGE_USE).host("web01").user("mbrowne").target("/usr/bin/shred -u /var/log/auth.log").message("x").build();
        assertThat(fired(List.of(routine, shell, wipe))).containsExactly("suspicious-sudo", "audit-log-cleared");
    }

    @Test
    void disabledRulesStaySilent() {
        engine.setEnabled("brute-force", false);
        List<Event> e = new ArrayList<>();
        for (int i = 0; i < 12; i++) e.add(ev(i, EventType.LOGIN_FAILURE, "root", "203.0.113.9"));
        assertThat(fired(e)).doesNotContain("brute-force");
    }

    /** The whole simulated day: every planted attack found, and nothing in the normal traffic flagged. */
    @Test
    void simulatedDayFindsEveryAttackAndNothingElse() {
        var day = new AttackSimulator(ZONE, 7).simulate(LocalDate.of(2025, 11, 6));
        var parsers = new Parsers(Clock.fixed(Instant.parse("2025-11-08T12:00:00Z"), ZONE), ZONE, "web01");
        var parsed = parsers.parse(String.join("", day.logs().values()), "auto");
        assertThat(parsed.skipped()).isZero();
        assertThat(parsed.events()).hasSize(day.lineCount());

        Map<String, Detection> alerts = new LinkedHashMap<>();
        for (var o : engine.process(parsed.events())) if (!o.repeat()) alerts.put(o.detection().ruleId() + "|" + o.detection().entity(), o.detection());

        List<String> matched = new ArrayList<>();
        for (var ex : day.expected()) {
            var hit = alerts.keySet().stream().filter(k -> k.startsWith(ex.ruleId() + "|") && k.contains(ex.entityContains())).findFirst();
            assertThat(hit).as("expected %s (%s): %s", ex.ruleId(), ex.entityContains(), ex.story()).isPresent();
            matched.add(hit.get());
        }
        assertThat(alerts.keySet()).as("alerts nobody planted (false positives)").containsExactlyInAnyOrderElementsOf(matched);
        assertThat(day.expected()).hasSize(22);
    }
}
