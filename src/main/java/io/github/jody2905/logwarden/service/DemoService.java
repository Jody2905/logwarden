package io.github.jody2905.logwarden.service;

import io.github.jody2905.logwarden.config.LogwardenProperties;
import io.github.jody2905.logwarden.core.detect.DetectionEngine;
import io.github.jody2905.logwarden.core.sim.AttackSimulator;
import io.github.jody2905.logwarden.domain.Repositories;
import io.github.jody2905.logwarden.domain.RuleSetting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;

/** Start-up (rule settings, warming the rules, demo data) and housekeeping. */
@Service
public class DemoService {

    private static final Logger log = LoggerFactory.getLogger(DemoService.class);

    private final IngestService ingest;
    private final DetectionEngine engine;
    private final Repositories.Events events;
    private final Repositories.Alerts alerts;
    private final Repositories.Notes notes;
    private final Repositories.RuleSettings settings;
    private final LogwardenProperties props;
    private final ZoneId zone;
    private final Clock clock;

    public DemoService(IngestService ingest, DetectionEngine engine, Repositories.Events events, Repositories.Alerts alerts,
                       Repositories.Notes notes, Repositories.RuleSettings settings, LogwardenProperties props, ZoneId zone, Clock clock) {
        this.ingest = ingest;
        this.engine = engine;
        this.events = events;
        this.alerts = alerts;
        this.notes = notes;
        this.settings = settings;
        this.props = props;
        this.zone = zone;
        this.clock = clock;
    }

    @EventListener(ApplicationReadyEvent.class)
    public void onStart() {
        settings.findAll().forEach(s -> engine.rule(s.getRuleId()).ifPresent(r -> engine.setEnabled(s.getRuleId(), s.isEnabled())));
        if (events.count() == 0 && props.demoData()) {
            var r = loadDemo(false);
            log.info("Loaded the demo day: {} events, {} alerts", r.stored(), r.alertsRaised());
            return;
        }
        // Replay recent history so the rules remember what they saw before the restart (no new alerts)
        Instant since = events.latestTime().orElse(clock.instant()).minus(Duration.ofHours(6));
        var recent = events.findByTimeAfterOrderByTimeAsc(since).stream().map(e -> e.toEvent()).toList();
        engine.process(recent);
        log.info("Rules warmed up with {} recent events", recent.size());
    }

    /** Load a simulated working day with attacks in it; with {@code wipe}, clear everything first. */
    @Transactional
    public IngestService.Result loadDemo(boolean wipe) {
        if (wipe) {
            notes.deleteAllInBatch();
            alerts.deleteAll();
            events.deleteAllInBatch();
            engine.reset();
        }
        var day = new AttackSimulator(zone, 7).simulate(AttackSimulator.recentWeekday(clock.instant(), zone));
        return ingest.ingest(String.join("", day.logs().values()), "auto");
    }

    public void setRule(String id, boolean on) {
        engine.setEnabled(id, on);
        settings.save(new RuleSetting(id, on));
    }

    /** Delete events past the retention period, once a day. Alerts stay, with their summary. */
    @Scheduled(cron = "0 15 3 * * *")
    @Transactional
    public void purge() {
        int n = events.deleteOlderThan(clock.instant().minus(Duration.ofDays(props.retentionDays())));
        if (n > 0) log.info("Deleted {} events older than {} days", n, props.retentionDays());
    }
}
