package io.github.jody2905.logwarden.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

/**
 * Who can do what:
 * <ul>
 *   <li>analyst: read everything, work alerts, upload logs</li>
 *   <li>admin: also switch rules on and off and reset the demo data</li>
 *   <li>log shippers: send logs to /api/ingest with the X-API-Key header, nothing else</li>
 * </ul>
 * The browser UI uses a session cookie with CSRF protection; API-key requests carry no cookie, so they skip CSRF.
 */
@Configuration
public class SecurityConfig {

    static final String API_KEY_HEADER = "X-API-Key";

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService users(LogwardenProperties p, PasswordEncoder enc) {
        return new InMemoryUserDetailsManager(
                User.withUsername("admin").password(enc.encode(p.adminPassword())).roles("ADMIN", "ANALYST").build(),
                User.withUsername("analyst").password(enc.encode(p.analystPassword())).roles("ANALYST").build());
    }

    @Bean
    SecurityFilterChain security(HttpSecurity http, LogwardenProperties p, LoginThrottle throttle) throws Exception {
        RequestMatcher apiKeyRequest = r -> r.getHeader(API_KEY_HEADER) != null;
        CsrfTokenRequestAttributeHandler csrfHandler = new CsrfTokenRequestAttributeHandler();
        csrfHandler.setCsrfRequestAttributeName(null); // send the token on every response, so the page always has it

        http
            .authorizeHttpRequests(a -> a
                .requestMatchers("/login.html", "/login.js", "/app.css", "/favicon.svg", "/actuator/health/**", "/error").permitAll()
                .requestMatchers(HttpMethod.POST, "/api/ingest", "/api/ingest/**").hasAnyRole("INGEST", "ANALYST")
                .requestMatchers(HttpMethod.PUT, "/api/rules/**").hasRole("ADMIN")
                .requestMatchers("/api/demo/**").hasRole("ADMIN")
                .requestMatchers("/api/**").hasRole("ANALYST")
                .anyRequest().hasRole("ANALYST"))
            .formLogin(f -> f.loginPage("/login.html").loginProcessingUrl("/login")
                .defaultSuccessUrl("/", true).failureUrl("/login.html?error").permitAll())
            .logout(l -> l.logoutUrl("/logout").logoutSuccessUrl("/login.html?out"))
            .csrf(c -> c.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .csrfTokenRequestHandler(csrfHandler)
                .ignoringRequestMatchers(apiKeyRequest))
            .exceptionHandling(e -> e.defaultAuthenticationEntryPointFor(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED), pathPattern("/api/**")))
            .headers(h -> h
                .contentSecurityPolicy(c -> c.policyDirectives("default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; frame-ancestors 'none'; form-action 'self'; base-uri 'none'"))
                .referrerPolicy(r -> r.policy(org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy.SAME_ORIGIN)))
            .addFilterBefore(new ApiKeyFilter(p.apiKey()), UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(throttle.filter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    /** Authenticates log shippers that send the right X-API-Key; refuses a wrong key outright. */
    static final class ApiKeyFilter extends OncePerRequestFilter {
        private final byte[] key;

        ApiKeyFilter(String key) {
            this.key = key == null || key.isBlank() ? null : key.getBytes(StandardCharsets.UTF_8);
        }

        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain) throws ServletException, IOException {
            String sent = req.getHeader(API_KEY_HEADER);
            if (sent != null) {
                boolean ok = key != null && req.getRequestURI().startsWith("/api/ingest")
                        && MessageDigest.isEqual(key, sent.getBytes(StandardCharsets.UTF_8));
                if (!ok) {
                    res.sendError(HttpServletResponse.SC_UNAUTHORIZED, key == null ? "API-key ingest is turned off (set LOGWARDEN_API_KEY)" : "Wrong API key");
                    return;
                }
                SecurityContextHolder.getContext().setAuthentication(
                        new UsernamePasswordAuthenticationToken("log-shipper", null, List.of(new SimpleGrantedAuthority("ROLE_INGEST"))));
            }
            chain.doFilter(req, res);
        }
    }
}
