package io.github.jody2905.logwarden.domain;

import io.github.jody2905.logwarden.core.Event;
import io.github.jody2905.logwarden.core.EventType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

import java.time.Instant;

@Entity
@Table(name = "events")
public class EventEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    @Column(name = "event_time", nullable = false)
    private Instant time;
    @Column(name = "received_at", nullable = false)
    private Instant receivedAt;
    @Column(nullable = false)
    private String source;
    private String host;
    @Enumerated(EnumType.STRING)
    @Column(name = "event_type", nullable = false)
    private EventType type;
    @Column(name = "user_name")
    private String user;
    @Column(name = "src_ip")
    private String srcIp;
    @Column(name = "dst_port")
    private Integer dstPort;
    private String target;
    private Integer status;
    private String message;
    private String raw;

    protected EventEntity() { }

    public static EventEntity from(Event e, Instant receivedAt) {
        EventEntity x = new EventEntity();
        x.time = e.time();
        x.receivedAt = receivedAt;
        x.source = e.source();
        x.host = cut(e.host(), 255);
        x.type = e.type();
        x.user = cut(e.user(), 255);
        x.srcIp = cut(e.srcIp(), 64);
        x.dstPort = e.dstPort();
        x.target = cut(e.target(), 1000);
        x.status = e.status();
        x.message = cut(e.message(), 1000);
        x.raw = cut(e.raw(), 8000);
        return x;
    }

    public Event toEvent() {
        return new Event(id, time, source, host, type, user, srcIp, dstPort, target, status, message, raw);
    }

    static String cut(String s, int max) {
        return s == null || s.length() <= max ? s : s.substring(0, max - 1) + "…";
    }

    public Long getId() { return id; }
    public Instant getTime() { return time; }
    public Instant getReceivedAt() { return receivedAt; }
    public String getSource() { return source; }
    public String getHost() { return host; }
    public EventType getType() { return type; }
    public String getUser() { return user; }
    public String getSrcIp() { return srcIp; }
    public Integer getDstPort() { return dstPort; }
    public String getTarget() { return target; }
    public Integer getStatus() { return status; }
    public String getMessage() { return message; }
    public String getRaw() { return raw; }
}
