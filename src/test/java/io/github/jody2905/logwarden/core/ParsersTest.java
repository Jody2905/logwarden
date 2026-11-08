package io.github.jody2905.logwarden.core;

import io.github.jody2905.logwarden.core.parse.Parsers;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;

class ParsersTest {

    final Parsers parsers = new Parsers(Clock.fixed(Instant.parse("2025-11-10T12:00:00Z"), ZoneOffset.UTC), ZoneId.of("UTC"), "web01");

    Event one(String line) {
        var r = parsers.parse(line, "auto");
        assertThat(r.events()).as("parsed: %s (skipped %s)", line, r.skippedSamples()).hasSize(1);
        return r.events().get(0);
    }

    @Test
    void sshFailureAndSuccess() {
        Event f = one("Nov  7 03:12:01 web01 sshd[2211]: Failed password for invalid user oracle from 203.0.113.10 port 51122 ssh2");
        assertThat(f.type()).isEqualTo(EventType.LOGIN_FAILURE);
        assertThat(f.user()).isEqualTo("oracle");
        assertThat(f.srcIp()).isEqualTo("203.0.113.10");
        assertThat(f.host()).isEqualTo("web01");
        assertThat(f.time()).isEqualTo(Instant.parse("2025-11-07T03:12:01Z"));

        Event s = one("2025-11-07T03:14:09.123456+00:00 app01 sshd[99]: Accepted publickey for deploy from 10.10.2.15 port 40112 ssh2: RSA SHA256:x");
        assertThat(s.type()).isEqualTo(EventType.LOGIN_SUCCESS);
        assertThat(s.user()).isEqualTo("deploy");
        assertThat(s.target()).isEqualTo("ssh/publickey");
    }

    @Test
    void syslogDateInTheFutureMeansLastYear() {
        // Logged on 30 December, read on 10 November: that was last year
        assertThat(one("Dec 30 10:00:00 web01 sshd[1]: Failed password for root from 198.51.100.1 port 1 ssh2").time())
                .isEqualTo(Instant.parse("2024-12-30T10:00:00Z"));
    }

    @Test
    void sudoUseraddUsermod() {
        Event sudo = one("Nov  7 14:04:20 app01 sudo:   deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow");
        assertThat(sudo.type()).isEqualTo(EventType.PRIVILEGE_USE);
        assertThat(sudo.user()).isEqualTo("deploy");
        assertThat(sudo.target()).isEqualTo("/usr/bin/cat /etc/shadow");

        Event add = one("Nov  7 14:05:20 app01 useradd[812]: new user: name=svc-backup, UID=1005, GID=1005, home=/home/svc-backup, shell=/bin/bash");
        assertThat(add.type()).isEqualTo(EventType.ACCOUNT_CREATED);
        assertThat(add.target()).isEqualTo("svc-backup");

        Event grp = one("Nov  7 14:05:35 app01 usermod[813]: add 'svc-backup' to group 'sudo'");
        assertThat(grp.type()).isEqualTo(EventType.GROUP_MEMBER_ADDED);
        assertThat(grp.user()).isEqualTo("svc-backup");
        assertThat(grp.target()).isEqualTo("sudo");
    }

    @Test
    void windowsEventsIncludingPowerShell5Dates() {
        Event logon = one("{\"TimeCreated\":\"2025-11-07T06:40:00Z\",\"EventID\":4624,\"Computer\":\"DC01\",\"TargetUserName\":\"dcharles\",\"IpAddress\":\"192.0.2.150\",\"LogonType\":\"10\"}");
        assertThat(logon.type()).isEqualTo(EventType.LOGIN_SUCCESS);
        assertThat(logon.srcIp()).isEqualTo("192.0.2.150");

        Event group = one("{\"TimeCreated\":\"/Date(1762497840000)/\",\"Id\":4732,\"MachineName\":\"DC01\",\"SubjectUserName\":\"dcharles\","
                + "\"MemberName\":\"CN=tempsupport,OU=Contractors,DC=office,DC=local\",\"TargetUserName\":\"Administrators\"}");
        assertThat(group.type()).isEqualTo(EventType.GROUP_MEMBER_ADDED);
        assertThat(group.user()).isEqualTo("tempsupport");
        assertThat(group.target()).isEqualTo("Administrators");
        assertThat(group.time()).isEqualTo(Instant.ofEpochMilli(1762497840000L));

        assertThat(one("{\"TimeCreated\":\"2025-11-07T06:50:00Z\",\"EventID\":1102,\"SubjectUserName\":\"dcharles\"}").type()).isEqualTo(EventType.LOG_CLEARED);
        // Computer accounts logging on are noise, not people
        assertThat(one("{\"TimeCreated\":\"2025-11-07T06:50:00Z\",\"EventID\":4624,\"TargetUserName\":\"WS12$\"}").type()).isEqualTo(EventType.OTHER);
    }

    @Test
    void webAndFirewall() {
        Event w = one("198.51.100.200 - - [07/Nov/2025:15:32:10 -0400] \"GET /services?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\" 200 4410 \"-\" \"sqlmap/1.8\"");
        assertThat(w.type()).isEqualTo(EventType.HTTP_REQUEST);
        assertThat(w.status()).isEqualTo(200);
        assertThat(w.time()).isEqualTo(Instant.parse("2025-11-07T19:32:10Z"));
        assertThat(w.host()).isEqualTo("web01");

        Event fw = one("Nov  7 09:47:02 fw01 kernel: [123.4] [UFW BLOCK] IN=eth0 OUT= SRC=203.0.113.140 DST=10.10.0.1 LEN=44 PROTO=TCP SPT=40001 DPT=3389 WINDOW=1024 SYN URGP=0");
        assertThat(fw.type()).isEqualTo(EventType.CONNECTION_BLOCKED);
        assertThat(fw.source()).isEqualTo("firewall");
        assertThat(fw.dstPort()).isEqualTo(3389);
        assertThat(fw.target()).isEqualTo("10.10.0.1");
    }

    @Test
    void mixedUploadAndUnknownLines() {
        var r = parsers.parse("""
                # a comment
                Nov  7 03:12:01 web01 sshd[1]: Failed password for root from 203.0.113.10 port 1 ssh2
                {"TimeCreated":"2025-11-07T06:40:00Z","EventID":4625,"TargetUserName":"kjohn","IpAddress":"198.51.100.70"}
                this is not a log line
                {"broken json
                """, "auto");
        assertThat(r.events()).hasSize(2);
        assertThat(r.skipped()).isEqualTo(2);
        assertThat(r.byFormat()).containsEntry("linux", 1).containsEntry("windows", 1);
    }
}
