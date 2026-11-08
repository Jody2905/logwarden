package io.github.jody2905.logwarden.core.detect;

import io.github.jody2905.logwarden.core.Detection;
import io.github.jody2905.logwarden.core.Event;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

/**
 * Runs every enabled rule over events in time order. A rule that keeps firing for the same thing
 * (the same attacking address, say) within the grouping window is reported as a repeat, so the
 * application adds it to the existing alert instead of opening a new one.
 */
public final class DetectionEngine {

    /** A detection, and whether it continues one already raised. */
    public record Outcome(Detection detection, boolean repeat) { }

    private final List<Rule> rules;
    private final Set<String> enabled;
    private final Duration groupWindow;
    private final Map<String, Instant> lastFired = new HashMap<>();

    public DetectionEngine(List<Rule> rules, Duration groupWindow) {
        this.rules = List.copyOf(rules);
        this.enabled = new LinkedHashSet<>(rules.stream().map(Rule::id).toList());
        this.groupWindow = groupWindow;
    }

    public List<Rule> rules() {
        return rules;
    }

    public Optional<Rule> rule(String id) {
        return rules.stream().filter(r -> r.id().equals(id)).findFirst();
    }

    public synchronized boolean isEnabled(String id) {
        return enabled.contains(id);
    }

    public synchronized void setEnabled(String id, boolean on) {
        if (rule(id).isEmpty()) throw new IllegalArgumentException("No rule " + id);
        if (on) enabled.add(id);
        else enabled.remove(id);
    }

    /** Feed events (sorted here by time) and collect what the rules report. */
    public synchronized List<Outcome> process(List<Event> events) {
        List<Event> sorted = new ArrayList<>(events);
        sorted.sort(Comparator.comparing(Event::time));
        List<Outcome> out = new ArrayList<>();
        for (Event e : sorted) out.addAll(process(e));
        return out;
    }

    public synchronized List<Outcome> process(Event e) {
        List<Outcome> out = new ArrayList<>();
        for (Rule r : rules) {
            // Disabled rules still watch, so turning one back on doesn't start from nothing
            List<Detection> found = r.onEvent(e);
            if (!enabled.contains(r.id())) continue;
            for (Detection d : found) {
                String key = d.ruleId() + "|" + d.entity();
                Instant prev = lastFired.get(key);
                boolean repeat = prev != null && Duration.between(prev, d.last()).compareTo(groupWindow) <= 0;
                lastFired.put(key, d.last());
                out.add(new Outcome(d, repeat));
            }
        }
        if (lastFired.size() > 50_000) lastFired.clear();
        return out;
    }

    public synchronized void reset() {
        rules.forEach(Rule::reset);
        lastFired.clear();
    }
}
