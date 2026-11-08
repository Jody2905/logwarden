package io.github.jody2905.logwarden.web;

import io.github.jody2905.logwarden.core.Severity;
import io.github.jody2905.logwarden.core.detect.DetectionEngine;
import io.github.jody2905.logwarden.domain.AlertEntity;
import io.github.jody2905.logwarden.domain.AlertNote;
import io.github.jody2905.logwarden.domain.Repositories;
import io.github.jody2905.logwarden.service.AlertService;
import io.github.jody2905.logwarden.service.StatsService;
import jakarta.persistence.criteria.Predicate;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.security.core.Authentication;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/** The alert queue and each alert's investigation. */
@RestController
@RequestMapping("/api/alerts")
@Validated
public class AlertController {

    public record AlertView(long id, String ruleId, String ruleName, String title, String description, String severity, String mitre,
                            String entity, Instant firstSeen, Instant lastSeen, int hits, String status, String assignee, int evidenceCount) { }

    public record NoteView(long id, String author, String body, Instant createdAt) {
        static NoteView of(AlertNote n) {
            return new NoteView(n.getId(), n.getAuthor(), n.getBody(), n.getCreatedAt());
        }
    }

    public record AlertDetail(AlertView alert, List<EventController.EventView> evidence, List<NoteView> notes) { }

    public record Change(AlertEntity.Status status, @Size(max = 100) String assignee) { }

    public record NewNote(@NotBlank @Size(max = 4000) String body) { }

    private final Repositories.Alerts alerts;
    private final Repositories.Events events;
    private final Repositories.Notes notes;
    private final AlertService service;
    private final DetectionEngine engine;

    public AlertController(Repositories.Alerts alerts, Repositories.Events events, Repositories.Notes notes, AlertService service, DetectionEngine engine) {
        this.alerts = alerts;
        this.events = events;
        this.notes = notes;
        this.service = service;
        this.engine = engine;
    }

    /** {@code status} is a comma list (NEW,INVESTIGATING) or "open"; {@code q} searches title and entity. */
    @GetMapping
    @Transactional(readOnly = true)
    public EventController.PageView<AlertView> list(@RequestParam(required = false) String status, @RequestParam(required = false) String severity,
                                                    @RequestParam(required = false) String rule, @RequestParam(required = false) String q,
                                                    @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "50") int size) {
        Specification<AlertEntity> spec = (root, query, cb) -> {
            List<Predicate> w = new ArrayList<>();
            if (EventController.notBlank(status)) {
                List<AlertEntity.Status> st = status.equalsIgnoreCase("open") ? List.copyOf(StatsService.OPEN)
                        : Arrays.stream(status.split(",")).map(s -> AlertEntity.Status.valueOf(s.strip().toUpperCase(Locale.ROOT))).toList();
                w.add(root.get("status").in(st));
            }
            if (EventController.notBlank(severity)) {
                w.add(root.get("severity").in(Arrays.stream(severity.split(",")).map(s -> Severity.valueOf(s.strip().toUpperCase(Locale.ROOT))).toList()));
            }
            if (EventController.notBlank(rule)) w.add(cb.equal(root.get("ruleId"), rule.strip()));
            if (EventController.notBlank(q)) {
                String like = "%" + q.strip().toLowerCase(Locale.ROOT).replace("%", "\\%").replace("_", "\\_") + "%";
                w.add(cb.or(cb.like(cb.lower(root.get("title")), like, '\\'), cb.like(cb.lower(root.get("entity")), like, '\\')));
            }
            return cb.and(w.toArray(Predicate[]::new));
        };
        Page<AlertEntity> p = alerts.findAll(spec, PageRequest.of(Math.max(0, page), Math.min(Math.max(1, size), 200), Sort.by(Sort.Direction.DESC, "lastSeen", "id")));
        return EventController.PageView.of(p, p.getContent().stream().map(this::view).toList());
    }

    @GetMapping("/{id}")
    @Transactional(readOnly = true)
    public AlertDetail get(@PathVariable long id) {
        AlertEntity a = service.get(id);
        var evidence = events.findByIdInOrderByTimeAsc(a.getEventIds()).stream().map(EventController.EventView::of).toList();
        var trail = notes.findByAlertIdOrderByCreatedAtAsc(id).stream().map(NoteView::of).toList();
        return new AlertDetail(view(a), evidence, trail);
    }

    @PatchMapping("/{id}")
    @Transactional
    public AlertView change(@PathVariable long id, @RequestBody Change c, Authentication who) {
        return view(service.update(id, c.status(), c.assignee(), who.getName()));
    }

    @PostMapping("/{id}/notes")
    public NoteView note(@PathVariable long id, @RequestBody @Validated NewNote n, Authentication who) {
        return NoteView.of(service.addNote(id, n.body(), who.getName()));
    }

    private AlertView view(AlertEntity a) {
        return new AlertView(a.getId(), a.getRuleId(), engine.rule(a.getRuleId()).map(r -> r.name()).orElse(a.getRuleId()), a.getTitle(),
                a.getDescription(), a.getSeverity().name(), a.getMitre(), a.getEntity(), a.getFirstSeen(), a.getLastSeen(), a.getHitCount(),
                a.getStatus().name(), a.getAssignee(), a.getEventIds().size());
    }
}
