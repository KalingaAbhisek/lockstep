package dev.authsync.config;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Counts entry changes (not requests) per account over a sliding minute. RequestRateLimitFilter limits
 * requests; a batch of up to 50 changes is one request, so without this a client could send 50 times more
 * database writes than the request limit suggests. The limit is well above a 500-account import.
 * Kept in memory per server instance, like the request limits (see DEPLOYMENT.md for a shared limit).
 */
@Component
public class OperationRateLimiter {
    static final int MAX_OPERATIONS_PER_MINUTE = 1200;
    private static final long WINDOW_MILLIS = 60_000;
    private final Cache<String, Deque<Long>> recent = Caffeine.newBuilder()
            .maximumSize(50_000).expireAfterAccess(Duration.ofMillis(2 * WINDOW_MILLIS)).build();
    /** Charge rotation work by vault size; consecutive rotations have no separate cooldown. */
    public RotationPermit reserveRotation(String subject, int entries) {
        require(subject, Math.max(1, entries));
        return new RotationPermit(subject, Math.max(1, entries));
    }

    public final class RotationPermit {
        private final String subject;
        private int charged;
        private RotationPermit(String subject, int charged) { this.subject = subject; this.charged = charged; }
        /** Charge the authoritative vault size before reading its collection, including failed rotations. */
        public synchronized void chargeRead(int entries) {
            int total = Math.max(1, entries);
            if (total > charged) { require(subject, total - charged); charged = total; }
        }

    }

    /** Thrown when an account sends more changes than allowed; answered with 429. */
    public static class RateLimitedException extends RuntimeException {
        public RateLimitedException() { this("Too many changes. Wait a minute and try again."); }
        public RateLimitedException(String message) { super(message); }
    }

    /** Reserves {@code count} operations for {@code subject}, or throws RateLimitedException (reserving none). */
    public void require(String subject, int count) {
        if (!tryAcquire(subject, count)) throw new RateLimitedException();
    }

    boolean tryAcquire(String subject, int count) {
        long now = System.currentTimeMillis();
        Deque<Long> times = recent.get(String.valueOf(subject), ignored -> new ArrayDeque<>());
        synchronized (times) {
            while (!times.isEmpty() && now - times.peekFirst() >= WINDOW_MILLIS) times.pollFirst();
            if (times.size() + Math.max(1, count) > MAX_OPERATIONS_PER_MINUTE) return false;
            for (int i = 0; i < Math.max(1, count); i++) times.addLast(now);
            return true;
        }
    }
}
