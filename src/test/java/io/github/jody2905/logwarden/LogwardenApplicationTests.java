package io.github.jody2905.logwarden;

import io.github.jody2905.logwarden.domain.Repositories;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.patch;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The web app end to end, on an in-memory database. */
@SpringBootTest(properties = {"logwarden.demo-data=false", "logwarden.api-key=test-key", "spring.datasource.url=jdbc:h2:mem:apitest;MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH"})
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
class LogwardenApplicationTests {

    static final String ATTACK = """
            Nov  6 14:02:00 app01 sshd[1]: Failed password for deploy from 198.51.100.140 port 1 ssh2
            Nov  6 14:02:09 app01 sshd[2]: Failed password for deploy from 198.51.100.140 port 2 ssh2
            Nov  6 14:02:18 app01 sshd[3]: Failed password for deploy from 198.51.100.140 port 3 ssh2
            Nov  6 14:02:27 app01 sshd[4]: Failed password for deploy from 198.51.100.140 port 4 ssh2
            Nov  6 14:02:36 app01 sshd[5]: Failed password for deploy from 198.51.100.140 port 5 ssh2
            Nov  6 14:03:20 app01 sshd[6]: Accepted password for deploy from 198.51.100.140 port 6 ssh2
            Nov  6 14:04:00 app01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash
            """;

    @Autowired MockMvc mvc;
    @Autowired Repositories.Alerts alerts;
    @Autowired Repositories.Events events;

    @BeforeEach
    void empty() {
        assertThat(events.count()).isZero();
    }

    @Test
    void signInIsRequired() throws Exception {
        mvc.perform(get("/api/stats")).andExpect(status().isUnauthorized());
        mvc.perform(get("/").accept(MediaType.TEXT_HTML)).andExpect(status().is3xxRedirection());
        mvc.perform(get("/login.html")).andExpect(status().isOk());
        mvc.perform(formLogin("/login").user("analyst").password("wrong")).andExpect(redirectedUrl("/login.html?error"));
        mvc.perform(formLogin("/login").user("analyst").password("logwarden-demo")).andExpect(redirectedUrl("/"));
    }

    @Test
    void logShipperSendsLogsAndAlertsAppear() throws Exception {
        mvc.perform(post("/api/ingest?format=linux").header("X-API-Key", "test-key").contentType(MediaType.TEXT_PLAIN).content(ATTACK))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.stored").value(7))
                .andExpect(jsonPath("$.alertsRaised").value(2));
        assertThat(alerts.findAll()).extracting(a -> a.getRuleId()).containsExactlyInAnyOrder("success-after-failures", "suspicious-sudo");

        // The key only sends logs: it can't read anything, and a wrong key is refused
        mvc.perform(get("/api/alerts").header("X-API-Key", "test-key")).andExpect(status().isUnauthorized());
        mvc.perform(post("/api/ingest").header("X-API-Key", "nope").contentType(MediaType.TEXT_PLAIN).content(ATTACK)).andExpect(status().isUnauthorized());

        mvc.perform(get("/api/alerts?status=open&severity=CRITICAL").with(user("analyst").roles("ANALYST")))
                .andExpect(jsonPath("$.total").value(1))
                .andExpect(jsonPath("$.items[0].title", containsString("deploy logged in after 5 failures")));
        mvc.perform(get("/api/events?ip=198.51.100.140").with(user("analyst").roles("ANALYST"))).andExpect(jsonPath("$.total").value(6));
        mvc.perform(get("/api/stats").with(user("analyst").roles("ANALYST")))
                .andExpect(jsonPath("$.openAlerts").value(2)).andExpect(jsonPath("$.criticalOpen").value(1));
    }

    @Test
    void analystsWorkAlertsWithCsrfProtection() throws Exception {
        mvc.perform(post("/api/ingest").with(user("analyst").roles("ANALYST")).with(csrf()).contentType(MediaType.TEXT_PLAIN).content(ATTACK))
                .andExpect(status().isOk());
        long id = alerts.findAll().stream().filter(a -> a.getRuleId().equals("suspicious-sudo")).findFirst().orElseThrow().getId();
        var analyst = user("jo").roles("ANALYST");

        mvc.perform(patch("/api/alerts/" + id).with(analyst).contentType(MediaType.APPLICATION_JSON).content("{\"status\":\"RESOLVED\"}"))
                .andExpect(status().isForbidden());  // no CSRF token
        mvc.perform(patch("/api/alerts/" + id).with(analyst).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"status\":\"INVESTIGATING\",\"assignee\":\"Jo\"}"))
                .andExpect(jsonPath("$.status").value("INVESTIGATING")).andExpect(jsonPath("$.assignee").value("Jo"));
        mvc.perform(post("/api/alerts/" + id + "/notes").with(analyst).with(csrf()).contentType(MediaType.APPLICATION_JSON)
                        .content("{\"body\":\"Disabled deploy and reset its keys.\"}"))
                .andExpect(status().isOk());
        mvc.perform(get("/api/alerts/" + id).with(analyst))
                .andExpect(jsonPath("$.evidence.length()").value(1))
                .andExpect(jsonPath("$.notes.length()").value(4))
                .andExpect(jsonPath("$.notes[3].author").value("jo"));
        mvc.perform(get("/api/alerts/999999").with(analyst)).andExpect(status().isNotFound());
    }

    @Test
    void onlyAdminsChangeRules() throws Exception {
        String off = "{\"enabled\":false}";
        mvc.perform(put("/api/rules/account-created").with(user("analyst").roles("ANALYST")).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(off))
                .andExpect(status().isForbidden());
        mvc.perform(put("/api/rules/account-created").with(user("admin").roles("ADMIN", "ANALYST")).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(off))
                .andExpect(jsonPath("$.enabled").value(false));
        mvc.perform(post("/api/demo/reset").with(user("analyst").roles("ANALYST")).with(csrf())).andExpect(status().isForbidden());
    }

    @Test
    void demoDayLoadsForAdmins() throws Exception {
        mvc.perform(post("/api/demo/reset").with(user("admin").roles("ADMIN", "ANALYST")).with(csrf()))
                .andExpect(jsonPath("$.stored").value(greaterThan(3000)))
                .andExpect(jsonPath("$.alertsRaised").value(22));
    }

    @Test
    void logwardenCatchesABruteForceAgainstItselfAndLocksTheAddressOut() throws Exception {
        for (int i = 0; i < 10; i++) {
            mvc.perform(formLogin("/login").user("admin").password("guess" + i)).andExpect(redirectedUrl("/login.html?error"));
        }
        // The 11th attempt is turned away before the password is checked, even the right one
        mvc.perform(formLogin("/login").user("admin").password("logwarden-admin")).andExpect(redirectedUrl("/login.html?locked"));
        assertThat(alerts.findAll()).extracting(a -> a.getRuleId()).contains("brute-force");
        assertThat(events.findAll()).allSatisfy(e -> assertThat(e.getSource()).isEqualTo("logwarden"));
    }

    @Test
    void badInputGetsAClearError() throws Exception {
        mvc.perform(post("/api/ingest?format=cobol").with(user("analyst").roles("ANALYST")).with(csrf()).contentType(MediaType.TEXT_PLAIN).content("x"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error", containsString("Unknown format")));
        mvc.perform(get("/api/events?type=NOPE").with(user("analyst").roles("ANALYST"))).andExpect(status().isBadRequest());
        assertThat(Map.of()).isEmpty();
    }
}
