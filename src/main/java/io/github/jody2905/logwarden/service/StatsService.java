package io.github.jody2905.logwarden.service;

import io.github.jody2905.logwarden.core.Severity;
import io.github.jody2905.logwarden.core.detect.DetectionEngine;
import io.github.jody2905.logwarden.domain.AlertEntity;
import io.github.jody2905.logwarden.domain.Repositories;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Comparator;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Figures for the overview page. */
@Service
public class StatsService {

    public static final EnumSet<AlertEntity.Status> OPEN = EnumSet.of(AlertEntity.Status.NEW, AlertEntity.Status.INVESTIGATING);

    public record Count(String key, String label, long count) { }

    public record Overview(Instant windowEnd, long eventsTotal, long events24h, long openAlerts, long criticalOpen,
                           List<Count> openBySeverity, List<Count> byStatus, List<Count> byRule, List<Count> bySource,
                           List<Count> noisyIps, List<Long> hourly, List<AlertSummary> priority) { }

    public record AlertSummary(long id, String title, String severity, String status, String ruleId, String mitre, Instant lastSeen, int hits) {
        static AlertSummary of(AlertEntity a) {
            return new AlertSummary(a.getId(), a.getTitle(), a.getSeverity().name(), a.getStatus().name(), a.getRuleId(), a.getMitre(), a.getLastSeen(), a.getHitCount());
        }
    }

    private final Repositories.Events events;
    private final Repositories.Alerts alerts;
    private final DetectionEngine engine;
    private final Clock clock;

    public StatsService(Repositories.Events events, Repositories.Alerts alerts, DetectionEngine engine, Clock clock) {
        this.events = events;
        this.alerts = alerts;
        this.engine = engine;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public Overview overview() {
        // The 24 hours shown end at the newest log event: "now" while logs are flowing, and still useful
        // when they stopped (or for the demo day)
        Instant latest = events.latestLogTime().orElse(clock.instant());
        Instant end = latest.truncatedTo(ChronoUnit.HOURS).plus(Duration.ofHours(1));
        Instant start = end.minus(Duration.ofHours(24));

        long[] hourly = new long[24];
        for (Instant t : events.timesSince(start)) {
            int h = (int) Duration.between(start, t).toHours();
            if (h >= 0 && h < 24) hourly[h]++;
        }
        long last24 = 0;
        for (long h : hourly) last24 += h;

        Map<String, Long> sev = new LinkedHashMap<>();
        for (Severity s : List.of(Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW)) sev.put(s.name(), 0L);
        for (Object[] r : alerts.countOpenBySeverity(OPEN)) sev.put(((Severity) r[0]).name(), (Long) r[1]);

        List<Count> byStatus = alerts.countByStatus().stream()
                .map(r -> new Count(((AlertEntity.Status) r[0]).name(), AlertService.label((AlertEntity.Status) r[0]), (Long) r[1])).toList();
        List<Count> byRule = alerts.countByRule().stream()
                .map(r -> new Count((String) r[0], engine.rule((String) r[0]).map(x -> x.name()).orElse((String) r[0]), (Long) r[1])).toList();
        List<Count> bySource = events.countBySource(start).stream().map(r -> new Count((String) r[0], (String) r[0], (Long) r[1]))
                .sorted(Comparator.comparingLong(Count::count).reversed()).toList();
        List<Count> noisy = events.topNoisyIps(start, PageRequest.of(0, 8)).stream().map(r -> new Count((String) r[0], (String) r[0], (Long) r[1])).toList();

        List<AlertSummary> priority = alerts.findByStatusIn(OPEN).stream()
                .sorted(Comparator.comparing(AlertEntity::getSeverity).reversed().thenComparing(AlertEntity::getLastSeen, Comparator.reverseOrder()))
                .limit(8).map(AlertSummary::of).toList();

        return new Overview(end, events.count(), last24, alerts.countByStatusIn(OPEN), sev.get("CRITICAL"),
                sev.entrySet().stream().map(e -> new Count(e.getKey(), e.getKey().charAt(0) + e.getKey().substring(1).toLowerCase(), e.getValue())).toList(),
                byStatus, byRule, bySource, noisy, java.util.Arrays.stream(hourly).boxed().toList(), priority);
    }
}
