package io.github.jody2905.logwarden.service;

import io.github.jody2905.logwarden.core.Severity;
import io.github.jody2905.logwarden.core.detect.DetectionEngine;
import io.github.jody2905.logwarden.domain.AlertEntity;
import io.github.jody2905.logwarden.domain.AlertNote;
import io.github.jody2905.logwarden.domain.Repositories;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.NoSuchElementException;

/** Turns detections into alerts, and records what analysts do with them. */
@Service
public class AlertService {

    public record Counts(int raised, int updated) { }

    private final Repositories.Alerts alerts;
    private final Repositories.Notes notes;
    private final Clock clock;

    public AlertService(Repositories.Alerts alerts, Repositories.Notes notes, Clock clock) {
        this.alerts = alerts;
        this.notes = notes;
        this.clock = clock;
    }

    /** New detections open alerts; repeats are added to the open alert for the same rule and entity. */
    @Transactional
    public Counts record(List<DetectionEngine.Outcome> outcomes) {
        int raised = 0, updated = 0;
        Instant now = clock.instant();
        for (DetectionEngine.Outcome o : outcomes) {
            var d = o.detection();
            var existing = o.repeat() ? alerts.findFirstByRuleIdAndEntityOrderByLastSeenDesc(d.ruleId(), cut(d.entity())) : java.util.Optional.<AlertEntity>empty();
            if (existing.isPresent() && existing.get().getStatus().open()) {
                AlertEntity a = existing.get();
                Severity before = a.getSeverity();
                a.update(d, now);
                if (a.getSeverity() != before) {
                    notes.save(new AlertNote(a.getId(), "LogWarden", "Severity raised from " + before + " to " + a.getSeverity() + ".", now));
                }
                updated++;
            } else {
                AlertEntity a = alerts.save(AlertEntity.from(d, now));
                notes.save(new AlertNote(a.getId(), "LogWarden", "Raised by the \"" + d.ruleId() + "\" rule.", now));
                raised++;
            }
        }
        return new Counts(raised, updated);
    }

    @Transactional
    public AlertEntity update(long id, AlertEntity.Status status, String assignee, String by) {
        AlertEntity a = get(id);
        Instant now = clock.instant();
        if (status != null && status != a.getStatus()) {
            notes.save(new AlertNote(id, by, "Status changed from " + label(a.getStatus()) + " to " + label(status) + ".", now));
            a.setStatus(status, now);
        }
        if (assignee != null && !assignee.equals(a.getAssignee() == null ? "" : a.getAssignee())) {
            a.setAssignee(assignee, now);
            notes.save(new AlertNote(id, by, a.getAssignee() == null ? "Unassigned." : "Assigned to " + a.getAssignee() + ".", now));
        }
        return a;
    }

    @Transactional
    public AlertNote addNote(long id, String body, String by) {
        get(id);
        if (body == null || body.isBlank()) throw new IllegalArgumentException("The note is empty");
        return notes.save(new AlertNote(id, by, body.strip(), clock.instant()));
    }

    public AlertEntity get(long id) {
        return alerts.findById(id).orElseThrow(() -> new NoSuchElementException("No alert " + id));
    }

    static String label(AlertEntity.Status s) {
        return switch (s) {
            case NEW -> "New";
            case INVESTIGATING -> "Investigating";
            case RESOLVED -> "Resolved";
            case FALSE_POSITIVE -> "False positive";
        };
    }

    private static String cut(String s) {
        return s.length() <= 300 ? s : s.substring(0, 299) + "…";
    }
}
