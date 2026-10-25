package dev.authsync.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Per-account request limits, so one account (or a stolen session) cannot flood the server or run up
 * database costs: changes, reads and sign-ins are counted separately over a sliding minute. Limits are kept
 * in memory per server instance (see DEPLOYMENT.md for a shared limit in front of the service).
 * Created in SecurityConfig (not a bean) so it runs once, after authentication.
 */
public class RequestRateLimitFilter extends OncePerRequestFilter {
    static final int MAX_WRITES_PER_MINUTE = 120;
    // Far above normal use: a client makes a few reads when it opens and then one every couple of minutes.
    static final int MAX_READS_PER_MINUTE = 300;
    static final int MAX_SIGN_INS_PER_MINUTE = 10;
    private static final long WINDOW_MILLIS = 60_000;
    private static final int MAX_TRACKED_KEYS = 50_000;
    // Bounded and evicted key by key (least recently used, or idle for two windows), never cleared wholesale,
    // so an attacker creating many keys cannot reset everyone else's counters.
    private final Cache<String, Deque<Long>> recent = Caffeine.newBuilder()
            .maximumSize(MAX_TRACKED_KEYS)
            .expireAfterAccess(Duration.ofMillis(2 * WINDOW_MILLIS))
            .build();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // HEAD is counted (as a read): Spring answers it with the GET handler, which does the same database work.
        return !request.getRequestURI().startsWith("/api/") || "OPTIONS".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication instanceof JwtAuthenticationToken jwt) {
            String subject = jwt.getToken().getSubject();
            boolean signIn = "POST".equalsIgnoreCase(request.getMethod()) && "/api/v1/session".equals(request.getRequestURI());
            boolean read = "GET".equalsIgnoreCase(request.getMethod()) || "HEAD".equalsIgnoreCase(request.getMethod());
            boolean allowed = signIn ? tryAcquire("sign-in\n" + subject, MAX_SIGN_INS_PER_MINUTE)
                    : read ? tryAcquire("read\n" + subject, MAX_READS_PER_MINUTE)
                    : tryAcquire("write\n" + subject, MAX_WRITES_PER_MINUTE);
            if (!allowed) {
                response.setStatus(429);
                response.setHeader("Retry-After", "60");
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"code\":\"RATE_LIMITED\",\"error\":\"Too many requests. Wait a minute and try again.\"}");
                return;
            }
        }
        chain.doFilter(request, response);
    }

    boolean tryAcquire(String key, int limit) {
        long now = System.currentTimeMillis();
        Deque<Long> times = recent.get(key, ignored -> new ArrayDeque<>());
        synchronized (times) {
            while (!times.isEmpty() && now - times.peekFirst() >= WINDOW_MILLIS) times.pollFirst();
            if (times.size() >= limit) return false;
            times.addLast(now);
            return true;
        }
    }
}
