package io.github.jody2905.logwarden.config;

import io.github.jody2905.logwarden.core.GeoLookup;
import io.github.jody2905.logwarden.core.detect.DetectionEngine;
import io.github.jody2905.logwarden.core.detect.Rules;
import io.github.jody2905.logwarden.core.parse.Parsers;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.time.Clock;
import java.time.Duration;
import java.time.ZoneId;
import java.util.Set;

/** Wires the plain-Java detection core into Spring. */
@Configuration
@EnableScheduling
@EnableConfigurationProperties(LogwardenProperties.class)
@EnableJpaRepositories(basePackages = "io.github.jody2905.logwarden.domain", considerNestedRepositories = true)
public class CoreConfig {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    ZoneId localZone(LogwardenProperties p) {
        return ZoneId.of(p.zone());
    }

    @Bean
    Parsers parsers(Clock clock, ZoneId zone, LogwardenProperties p) {
        return new Parsers(clock, zone, p.webHost());
    }

    @Bean
    Rules.Config rulesConfig(ZoneId zone, LogwardenProperties p) {
        return new Rules.Config(zone, p.workStartHour(), p.workEndHour(),
                p.badIps() == null ? Set.of() : Set.copyOf(p.badIps()), GeoLookup.withSampleRanges());
    }

    @Bean
    DetectionEngine detectionEngine(Rules.Config config, LogwardenProperties p) {
        return new DetectionEngine(Rules.all(config), Duration.ofMinutes(p.groupWindowMinutes()));
    }
}
