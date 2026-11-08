package io.github.jody2905.logwarden.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.List;

/**
 * Settings under {@code logwarden.*} in application.properties (or environment variables such as LOGWARDEN_API_KEY).
 *
 * @param zone               local time zone for working hours, and for syslog lines that have no zone
 * @param workStartHour      working day starts (local time)
 * @param workEndHour        working day ends
 * @param webHost            host name given to web access-log events
 * @param badIps             threat-intelligence block list
 * @param groupWindowMinutes repeats of an alert within this many minutes are added to it
 * @param retentionDays      events older than this are deleted (alerts keep their summary)
 * @param apiKey             key log shippers send in the X-API-Key header (blank = API-key ingest off)
 * @param adminPassword      password for the "admin" user
 * @param analystPassword    password for the "analyst" user
 * @param demoData           load a simulated day of logs when the database is empty
 * @param maxUploadLines     largest upload accepted at once
 */
@ConfigurationProperties(prefix = "logwarden")
public record LogwardenProperties(String zone, int workStartHour, int workEndHour, String webHost, List<String> badIps,
                                  int groupWindowMinutes, int retentionDays, String apiKey, String adminPassword,
                                  String analystPassword, boolean demoData, int maxUploadLines) {
}
