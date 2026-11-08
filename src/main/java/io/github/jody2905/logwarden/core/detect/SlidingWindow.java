package io.github.jody2905.logwarden.core.detect;

import io.github.jody2905.logwarden.core.Event;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Events per key (an IP, a user) over the last {@code length} of event time. */
final class SlidingWindow {

    private final Duration length;
    private final int maxPerKey;
    private final Map<String, Deque<Event>> byKey = new HashMap<>();
    private Instant lastPrune = Instant.EPOCH;

    SlidingWindow(Duration length) {
        this(length, 2_000);
    }

    SlidingWindow(Duration length, int maxPerKey) {
        this.length = length;
        this.maxPerKey = maxPerKey;
    }

    /** Add an event and return everything for its key still inside the window. */
    List<Event> add(String key, Event e) {
        Deque<Event> q = byKey.computeIfAbsent(key, k -> new ArrayDeque<>());
        q.addLast(e);
        trim(q, e.time());
        while (q.size() > maxPerKey) q.removeFirst();
        pruneAll(e.time());
        return List.copyOf(q);
    }

    /** Events for a key inside the window ending at {@code now}, without adding one. */
    List<Event> get(String key, Instant now) {
        Deque<Event> q = byKey.get(key);
        if (q == null) return List.of();
        trim(q, now);
        return List.copyOf(q);
    }

    void clear(String key) {
        byKey.remove(key);
    }

    void reset() {
        byKey.clear();
    }

    private void trim(Deque<Event> q, Instant now) {
        Instant cutoff = now.minus(length);
        while (!q.isEmpty() && q.peekFirst().time().isBefore(cutoff)) q.removeFirst();
    }

    /** Drop idle keys now and then so memory stays flat. */
    private void pruneAll(Instant now) {
        if (Duration.between(lastPrune, now).compareTo(length) < 0) return;
        lastPrune = now;
        byKey.values().removeIf(q -> {
            trim(q, now);
            return q.isEmpty();
        });
    }
}
