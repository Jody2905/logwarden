package io.github.jody2905.logwarden.service;

import io.github.jody2905.logwarden.core.Event;
import io.github.jody2905.logwarden.core.EventType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.util.List;

/** LogWarden watches itself: every sign-in to it becomes an event, so its own rules catch attacks on it. */
@Component
public class SelfAudit {

    private static final Logger log = LoggerFactory.getLogger(SelfAudit.class);

    private final IngestService ingest;
    private final Clock clock;

    public SelfAudit(IngestService ingest, Clock clock) {
        this.ingest = ingest;
        this.clock = clock;
    }

    @EventListener
    public void signedIn(InteractiveAuthenticationSuccessEvent e) {
        record(e.getAuthentication(), EventType.LOGIN_SUCCESS, "Signed in to LogWarden");
    }

    @EventListener
    public void failed(AbstractAuthenticationFailureEvent e) {
        record(e.getAuthentication(), EventType.LOGIN_FAILURE, "Failed sign-in to LogWarden");
    }

    private void record(Authentication a, EventType type, String what) {
        if (!(a.getDetails() instanceof WebAuthenticationDetails d)) return;  // API keys and tests
        String user = a.getName(), ip = d.getRemoteAddress();
        try {
            ingest.record(List.of(Event.at(clock.instant(), "logwarden", type).host("logwarden").user(user).srcIp(ip)
                    .target("web sign-in").message(what + " as " + user + " from " + ip).build()));
        } catch (RuntimeException ex) {
            log.warn("Could not record sign-in event: {}", ex.getMessage());
        }
    }
}
