package io.github.jody2905.logwarden.web;

import io.github.jody2905.logwarden.config.LogwardenProperties;
import io.github.jody2905.logwarden.core.detect.DetectionEngine;
import io.github.jody2905.logwarden.core.detect.Rule;
import io.github.jody2905.logwarden.domain.Repositories;
import io.github.jody2905.logwarden.service.DemoService;
import io.github.jody2905.logwarden.service.IngestService;
import io.github.jody2905.logwarden.service.StatsService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

/** Overview figures, rules, the signed-in user and the demo data. */
@RestController
@RequestMapping("/api")
public class AppController {

    public record Me(String name, List<String> roles, boolean apiKeyIngest, String zone) { }

    public record RuleView(String id, String name, String description, String mitre, String severity, boolean enabled, long alerts) { }

    public record Toggle(boolean enabled) { }

    private final StatsService stats;
    private final DetectionEngine engine;
    private final DemoService demo;
    private final Repositories.Alerts alerts;
    private final LogwardenProperties props;

    public AppController(StatsService stats, DetectionEngine engine, DemoService demo, Repositories.Alerts alerts, LogwardenProperties props) {
        this.stats = stats;
        this.engine = engine;
        this.demo = demo;
        this.alerts = alerts;
        this.props = props;
    }

    @GetMapping("/me")
    public Me me(Authentication who) {
        List<String> roles = who.getAuthorities().stream().map(GrantedAuthority::getAuthority)
                .filter(r -> r.startsWith("ROLE_")).map(r -> r.substring(5)).toList();
        return new Me(who.getName(), roles, props.apiKey() != null && !props.apiKey().isBlank(), props.zone());
    }

    @GetMapping("/stats")
    public StatsService.Overview overview() {
        return stats.overview();
    }

    @GetMapping("/rules")
    public List<RuleView> rules() {
        Map<String, Long> counts = alerts.countByRule().stream().collect(Collectors.toMap(r -> (String) r[0], r -> (Long) r[1]));
        return engine.rules().stream().map(r -> view(r, counts.getOrDefault(r.id(), 0L))).toList();
    }

    @PutMapping("/rules/{id}")
    public RuleView toggle(@PathVariable String id, @RequestBody Toggle t) {
        demo.setRule(id, t.enabled());
        Rule r = engine.rule(id).orElseThrow();
        return view(r, 0);
    }

    @PostMapping("/demo/reset")
    public IngestService.Result reset() {
        return demo.loadDemo(true);
    }

    private RuleView view(Rule r, long count) {
        return new RuleView(r.id(), r.name(), r.description(), r.mitre(), r.severity().name(), engine.isEnabled(r.id()), count);
    }
}
