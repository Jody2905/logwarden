package io.github.jody2905.logwarden;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

@SpringBootApplication
public class LogwardenApplication {

    public static void main(String[] args) {
        useDatabaseUrl(System.getenv("DATABASE_URL"));
        SpringApplication.run(LogwardenApplication.class, args);
    }

    /**
     * Hosts like Neon and Render give a URL such as postgresql://user:pass@host/db?sslmode=require.
     * Spring needs JDBC form with the user and password separate, so convert it here.
     */
    static void useDatabaseUrl(String url) {
        if (url == null || url.isBlank() || System.getenv("JDBC_DATABASE_URL") != null) return;
        if (url.startsWith("jdbc:")) {
            System.setProperty("JDBC_DATABASE_URL", url);
            return;
        }
        URI u = URI.create(url.replaceFirst("^postgres(ql)?://", "http://"));
        String query = u.getRawQuery() == null ? "sslmode=require" : u.getRawQuery();
        System.setProperty("JDBC_DATABASE_URL", "jdbc:postgresql://" + u.getHost() + (u.getPort() > 0 ? ":" + u.getPort() : "") + u.getRawPath() + "?" + query);
        if (u.getRawUserInfo() != null) {
            String[] up = u.getRawUserInfo().split(":", 2);
            System.setProperty("JDBC_DATABASE_USERNAME", URLDecoder.decode(up[0], StandardCharsets.UTF_8));
            if (up.length > 1) System.setProperty("JDBC_DATABASE_PASSWORD", URLDecoder.decode(up[1], StandardCharsets.UTF_8));
        }
    }
}
