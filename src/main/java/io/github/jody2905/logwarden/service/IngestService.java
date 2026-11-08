package io.github.jody2905.logwarden.service;

import io.github.jody2905.logwarden.config.LogwardenProperties;
import io.github.jody2905.logwarden.core.Event;
import io.github.jody2905.logwarden.core.detect.DetectionEngine;
import io.github.jody2905.logwarden.core.parse.Parsers;
import io.github.jody2905.logwarden.domain.EventEntity;
import io.github.jody2905.logwarden.domain.Repositories;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Map;

/** Parses uploaded log text, stores the events and runs them through the detection rules. */
@Service
public class IngestService {

    public record Result(int lines, int stored, int skipped, Map<String, Integer> byFormat, List<String> skippedSamples,
                         int alertsRaised, int alertsUpdated, Instant from, Instant to) { }

    private final Parsers parsers;
    private final DetectionEngine engine;
    private final Repositories.Events events;
    private final AlertService alerts;
    private final LogwardenProperties props;
    private final Clock clock;

    public IngestService(Parsers parsers, DetectionEngine engine, Repositories.Events events, AlertService alerts,
                         LogwardenProperties props, Clock clock) {
        this.parsers = parsers;
        this.engine = engine;
        this.events = events;
        this.alerts = alerts;
        this.props = props;
        this.clock = clock;
    }

    /** Parse text in the given format ("auto" detects it per line), store it and check it. */
    @Transactional
    public synchronized Result ingest(String text, String format) {
        long lines = text.lines().count();
        if (lines > props.maxUploadLines()) {
            throw new IllegalArgumentException("Too many lines (" + lines + "). Send at most " + props.maxUploadLines() + " at a time.");
        }
        Parsers.Result parsed = parsers.parse(text, format);
        AlertService.Counts c = store(parsed.events());
        List<Event> evs = parsed.events();
        Instant from = evs.stream().map(Event::time).min(Comparator.naturalOrder()).orElse(null);
        Instant to = evs.stream().map(Event::time).max(Comparator.naturalOrder()).orElse(null);
        return new Result(parsed.lines(), evs.size(), parsed.skipped(), parsed.byFormat(), parsed.skippedSamples(), c.raised(), c.updated(), from, to);
    }

    /** Store events that were made in code (LogWarden's own sign-ins) and check them. */
    @Transactional
    public synchronized AlertService.Counts record(List<Event> list) {
        return store(list);
    }

    private AlertService.Counts store(List<Event> list) {
        if (list.isEmpty()) return new AlertService.Counts(0, 0);
        List<Event> sorted = new ArrayList<>(list);
        sorted.sort(Comparator.comparing(Event::time));
        Instant now = clock.instant();
        List<Event> saved = new ArrayList<>(sorted.size());
        for (int i = 0; i < sorted.size(); i += 500) {
            List<EventEntity> batch = sorted.subList(i, Math.min(sorted.size(), i + 500)).stream().map(e -> EventEntity.from(e, now)).toList();
            events.saveAll(batch).forEach(x -> saved.add(x.toEvent()));
        }
        return alerts.record(engine.process(saved));
    }
}
