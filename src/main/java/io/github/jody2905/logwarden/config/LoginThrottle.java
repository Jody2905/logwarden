package io.github.jody2905.logwarden.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/** After 10 failed sign-ins from one address in 15 minutes, refuse further attempts from it for 15 minutes. */
@Component
public class LoginThrottle {

    static final int MAX_FAILURES = 10;
    static final Duration WINDOW = Duration.ofMinutes(15);

    private final Map<String, Deque<Instant>> failures = new ConcurrentHashMap<>();
    private final Clock clock;

    public LoginThrottle(Clock clock) {
        this.clock = clock;
    }

    /** The servlet filter that turns away locked-out addresses before their password is checked. */
    OncePerRequestFilter filter() {
        return new OncePerRequestFilter() {
            @Override
            protected boolean shouldNotFilter(HttpServletRequest req) {
                return !("POST".equals(req.getMethod()) && "/login".equals(req.getRequestURI()));
            }

            @Override
            protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
                if (blocked(req.getRemoteAddr())) {
                    res.sendRedirect("/login.html?locked");
                    return;
                }
                chain.doFilter(req, res);
            }
        };
    }

    boolean blocked(String ip) {
        Deque<Instant> q = failures.get(ip);
        if (q == null) return false;
        synchronized (q) {
            Instant cutoff = clock.instant().minus(WINDOW);
            while (!q.isEmpty() && q.peekFirst().isBefore(cutoff)) q.removeFirst();
            return q.size() >= MAX_FAILURES;
        }
    }

    @EventListener
    public void failed(AbstractAuthenticationFailureEvent e) {
        if (!(e.getAuthentication().getDetails() instanceof WebAuthenticationDetails d)) return;
        Deque<Instant> q = failures.computeIfAbsent(d.getRemoteAddress(), k -> new ArrayDeque<>());
        synchronized (q) {
            q.addLast(clock.instant());
            while (q.size() > MAX_FAILURES * 2) q.removeFirst();
        }
        if (failures.size() > 10_000) failures.clear();
    }

    @EventListener
    public void succeeded(AuthenticationSuccessEvent e) {
        if (e.getAuthentication().getDetails() instanceof WebAuthenticationDetails d) failures.remove(d.getRemoteAddress());
    }
}
