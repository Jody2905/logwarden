package io.github.jody2905.logwarden.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

/** One entry in an alert's investigation trail: an analyst's note or a recorded status change. */
@Entity
@Table(name = "alert_notes")
public class AlertNote {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "alert_id", nullable = false)
    private Long alertId;
    @Column(nullable = false)
    private String author;
    @Column(nullable = false)
    private String body;
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    protected AlertNote() { }

    public AlertNote(Long alertId, String author, String body, Instant createdAt) {
        this.alertId = alertId;
        this.author = author;
        this.body = EventEntity.cut(body, 4000);
        this.createdAt = createdAt;
    }

    public Long getId() { return id; }
    public Long getAlertId() { return alertId; }
    public String getAuthor() { return author; }
    public String getBody() { return body; }
    public Instant getCreatedAt() { return createdAt; }
}
