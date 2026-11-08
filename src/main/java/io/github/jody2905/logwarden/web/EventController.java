package io.github.jody2905.logwarden.web;

import io.github.jody2905.logwarden.core.EventType;
import io.github.jody2905.logwarden.domain.EventEntity;
import io.github.jody2905.logwarden.domain.Repositories;
import jakarta.persistence.criteria.Predicate;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Searching the stored events. */
@RestController
@RequestMapping("/api/events")
public class EventController {

    public record EventView(long id, Instant time, String source, String host, String type, String typeLabel, String user,
                            String srcIp, Integer dstPort, String target, Integer status, String message, String raw) {
        static EventView of(EventEntity e) {
            return new EventView(e.getId(), e.getTime(), e.getSource(), e.getHost(), e.getType().name(), e.getType().label(), e.getUser(),
                    e.getSrcIp(), e.getDstPort(), e.getTarget(), e.getStatus(), e.getMessage(), e.getRaw());
        }
    }

    public record PageView<T>(List<T> items, long total, int page, int size, int pages) {
        static <T> PageView<T> of(Page<?> p, List<T> items) {
            return new PageView<>(items, p.getTotalElements(), p.getNumber(), p.getSize(), p.getTotalPages());
        }
    }

    private final Repositories.Events events;

    public EventController(Repositories.Events events) {
        this.events = events;
    }

    /**
     * Search. {@code q} matches anywhere in the message or raw line; the other filters are exact
     * (user is case-insensitive). Times are ISO-8601, e.g. 2026-11-06T14:00:00Z.
     */
    @GetMapping
    public PageView<EventView> search(@RequestParam(required = false) String q, @RequestParam(required = false) String type,
                                      @RequestParam(required = false) String source, @RequestParam(required = false) String ip,
                                      @RequestParam(required = false) String user, @RequestParam(required = false) String host,
                                      @RequestParam(required = false) Instant from, @RequestParam(required = false) Instant to,
                                      @RequestParam(defaultValue = "0") int page, @RequestParam(defaultValue = "50") int size) {
        Specification<EventEntity> spec = (root, query, cb) -> {
            List<Predicate> w = new ArrayList<>();
            if (notBlank(q)) {
                String like = "%" + q.strip().toLowerCase(Locale.ROOT).replace("%", "\\%").replace("_", "\\_") + "%";
                w.add(cb.or(cb.like(cb.lower(root.get("message")), like, '\\'), cb.like(cb.lower(root.get("raw")), like, '\\')));
            }
            if (notBlank(type)) w.add(cb.equal(root.get("type"), EventType.valueOf(type.strip().toUpperCase(Locale.ROOT))));
            if (notBlank(source)) w.add(cb.equal(root.get("source"), source.strip()));
            if (notBlank(ip)) w.add(cb.equal(root.get("srcIp"), ip.strip()));
            if (notBlank(user)) w.add(cb.equal(cb.lower(root.get("user")), user.strip().toLowerCase(Locale.ROOT)));
            if (notBlank(host)) w.add(cb.equal(root.get("host"), host.strip()));
            if (from != null) w.add(cb.greaterThanOrEqualTo(root.get("time"), from));
            if (to != null) w.add(cb.lessThan(root.get("time"), to));
            return cb.and(w.toArray(Predicate[]::new));
        };
        Page<EventEntity> p = events.findAll(spec, PageRequest.of(Math.max(0, page), Math.min(Math.max(1, size), 200), Sort.by(Sort.Direction.DESC, "time", "id")));
        return PageView.of(p, p.getContent().stream().map(EventView::of).toList());
    }

    static boolean notBlank(String s) {
        return s != null && !s.isBlank();
    }
}
