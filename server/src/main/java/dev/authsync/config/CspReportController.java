package dev.authsync.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Receives the browser's reports of content the web app's security policy blocked, or would block once
 * Trusted Types are enforced (the {@code report-uri} in webapp/nginx.conf and firebase.json), and writes a
 * short line per report to the log. That shows real problems, for example from Google's sign-in script,
 * before Trusted Types are switched from report-only to enforced.
 *
 * Browsers send these reports without signing in, so the endpoint is public. It reads at most 8 KiB, logs
 * only a few cleaned-up fields (never the page's query string or the script sample), accepts at most 20 reports per minute from
 * one address (the rest are dropped silently), and never touches Firestore.
 */
@RestController
public class CspReportController {
    private static final Logger log = LoggerFactory.getLogger(CspReportController.class);
    static final String PATH = "/api/v1/csp-report";
    static final int MAX_BODY_BYTES = 8 * 1024;
    static final int MAX_REPORTS_PER_MINUTE = 20;
    private static final long WINDOW_MILLIS = 60_000;
    private final Cache<String, Deque<Long>> recent = Caffeine.newBuilder()
            .maximumSize(10_000).expireAfterAccess(Duration.ofMillis(2 * WINDOW_MILLIS)).build();

    @PostMapping(PATH)
    ResponseEntity<Void> report(HttpServletRequest request) throws IOException {
        if (!tryAcquire(request.getRemoteAddr())) return ResponseEntity.noContent().build();
        String body;
        try (InputStream input = request.getInputStream()) {
            body = new String(input.readNBytes(MAX_BODY_BYTES), StandardCharsets.UTF_8);
        }
        // Old format: {"csp-report": {...}}; Reporting API: [{"type":"csp-violation","body":{...}}]. Both use
        // these names (Reporting API in camelCase), so the fields are picked out without a full parse.
        String directive = field(body, "effective-directive", "effectiveDirective", "violated-directive");
        if (directive.isEmpty()) return ResponseEntity.noContent().build();
        // The report's script sample is never logged: it is page content the browser copies into the report.
        log.warn("Content-Security-Policy report: directive={} blocked={} source={} line={} page={} disposition={}",
                directive,
                withoutQuery(field(body, "blocked-uri", "blockedURL")),
                withoutQuery(field(body, "source-file", "sourceFile")),
                field(body, "line-number", "lineNumber"),
                withoutQuery(field(body, "document-uri", "documentURL")),
                field(body, "disposition"));
        return ResponseEntity.noContent().build();
    }

    boolean tryAcquire(String address) {
        long now = System.currentTimeMillis();
        Deque<Long> times = recent.get(address == null ? "unknown" : address, ignored -> new ArrayDeque<>());
        synchronized (times) {
            while (!times.isEmpty() && now - times.peekFirst() >= WINDOW_MILLIS) times.pollFirst();
            if (times.size() >= MAX_REPORTS_PER_MINUTE) return false;
            times.addLast(now);
            return true;
        }
    }

    /** The first of the named JSON fields (string or number), cleaned up for a log line; "" when absent. */
    static String field(String body, String... names) {
        for (String name : names) {
            Matcher matcher = Pattern.compile("\"" + Pattern.quote(name) + "\"\\s*:\\s*(\"((?:[^\"\\\\]|\\\\.){0,600})\"|-?\\d{1,9})").matcher(body);
            if (matcher.find()) return clean(matcher.group(2) != null ? matcher.group(2) : matcher.group(1));
        }
        return "";
    }

    /** Printable characters only (no line breaks that could forge log lines), at most 200. */
    static String clean(String value) {
        String printable = value.replaceAll("\\\\[nrt]", " ").replaceAll("[^\\x20-\\x7E]", "?");
        return printable.length() > 200 ? printable.substring(0, 200) + "…" : printable;
    }

    /** Page and script addresses without their query string or fragment (they may carry tokens). */
    static String withoutQuery(String value) {
        int cut = value.length();
        for (char marker : new char[] {'?', '#'}) {
            int index = value.indexOf(marker);
            if (index >= 0 && index < cut) cut = index;
        }
        return value.substring(0, cut);
    }
}
