package io.github.jody2905.logwarden.domain;

import io.github.jody2905.logwarden.core.Detection;
import io.github.jody2905.logwarden.core.Severity;
import jakarta.persistence.CollectionTable;
import jakarta.persistence.Column;
import jakarta.persistence.ElementCollection;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.Table;

import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Set;

@Entity
@Table(name = "alerts")
public class AlertEntity {

    public enum Status { NEW, INVESTIGATING, RESOLVED, FALSE_POSITIVE;
        public boolean open() { return this == NEW || this == INVESTIGATING; }
    }

    /** Most events kept as evidence on one alert. */
    public static final int MAX_EVIDENCE = 200;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "rule_id", nullable = false)
    private String ruleId;
    @Column(nullable = false)
    private String title;
    @Column(nullable = false)
    private String description;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;
    private String mitre;
    @Column(nullable = false)
    private String entity;
    @Column(name = "first_seen", nullable = false)
    private Instant firstSeen;
    @Column(name = "last_seen", nullable = false)
    private Instant lastSeen;
    @Column(name = "hit_count", nullable = false)
    private int hitCount;
    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Status status;
    private String assignee;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "alert_events", joinColumns = @JoinColumn(name = "alert_id"))
    @Column(name = "event_id")
    private Set<Long> eventIds = new LinkedHashSet<>();

    protected AlertEntity() { }

    public static AlertEntity from(Detection d, Instant now) {
        AlertEntity a = new AlertEntity();
        a.ruleId = d.ruleId();
        a.entity = EventEntity.cut(d.entity(), 300);
        a.firstSeen = d.first();
        a.lastSeen = d.last();
        a.hitCount = 0;
        a.severity = d.severity();
        a.status = Status.NEW;
        a.createdAt = now;
        a.update(d, now);
        return a;
    }

    /** The rule fired again for the same thing: take the newest wording and evidence, keep the worst severity. */
    public void update(Detection d, Instant now) {
        title = EventEntity.cut(d.title(), 300);
        description = EventEntity.cut(d.description(), 2000);
        mitre = d.mitre();
        severity = severity.atLeast(d.severity());
        if (d.first().isBefore(firstSeen)) firstSeen = d.first();
        if (d.last().isAfter(lastSeen)) lastSeen = d.last();
        hitCount++;
        for (var e : d.evidence()) {
            if (eventIds.size() >= MAX_EVIDENCE) break;
            if (e.id() != null) eventIds.add(e.id());
        }
        updatedAt = now;
    }

    public void setStatus(Status s, Instant now) {
        status = s;
        updatedAt = now;
    }

    public void setAssignee(String a, Instant now) {
        assignee = a == null || a.isBlank() ? null : EventEntity.cut(a.strip(), 100);
        updatedAt = now;
    }

    public Long getId() { return id; }
    public String getRuleId() { return ruleId; }
    public String getTitle() { return title; }
    public String getDescription() { return description; }
    public Severity getSeverity() { return severity; }
    public String getMitre() { return mitre; }
    public String getEntity() { return entity; }
    public Instant getFirstSeen() { return firstSeen; }
    public Instant getLastSeen() { return lastSeen; }
    public int getHitCount() { return hitCount; }
    public Status getStatus() { return status; }
    public String getAssignee() { return assignee; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public Set<Long> getEventIds() { return eventIds; }
}
