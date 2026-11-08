package io.github.jody2905.logwarden.web;

import io.github.jody2905.logwarden.core.parse.LogParser;
import io.github.jody2905.logwarden.core.parse.Parsers;
import io.github.jody2905.logwarden.service.IngestService;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Getting logs in.
 * <pre>
 * curl -X POST "https://your-logwarden/api/ingest?format=linux" -H "X-API-Key: $KEY" --data-binary @/var/log/auth.log
 * </pre>
 */
@RestController
@RequestMapping("/api")
public class IngestController {

    public record Format(String name, String description) { }

    private final IngestService ingest;
    private final Parsers parsers;

    public IngestController(IngestService ingest, Parsers parsers) {
        this.ingest = ingest;
        this.parsers = parsers;
    }

    /** Raw log text in the body. */
    @PostMapping(value = "/ingest", consumes = {MediaType.TEXT_PLAIN_VALUE, MediaType.APPLICATION_OCTET_STREAM_VALUE, "application/x-ndjson", MediaType.ALL_VALUE})
    public IngestService.Result text(@RequestBody String body, @RequestParam(defaultValue = "auto") String format) {
        return ingest.ingest(body, format);
    }

    /** A log file from the upload page. */
    @PostMapping(value = "/ingest/file", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public IngestService.Result file(@RequestPart("file") MultipartFile file, @RequestParam(defaultValue = "auto") String format) throws IOException {
        if (file.isEmpty()) throw new IllegalArgumentException("The file is empty");
        return ingest.ingest(new String(file.getBytes(), StandardCharsets.UTF_8), format);
    }

    @GetMapping("/formats")
    public List<Format> formats() {
        return parsers.all().stream().map((LogParser p) -> new Format(p.name(), p.description())).toList();
    }
}
