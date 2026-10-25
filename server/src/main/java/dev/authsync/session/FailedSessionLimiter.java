package dev.authsync.session;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.ArrayDeque;
import java.util.Deque;

/**
 * Limits the session lookups (Firestore reads) one client address can cause with sessions that turn out to
 * be wrong: over a sliding minute, the refused lookups plus the lookups still in progress may not exceed
 * {@link #MAX_FAILURES_PER_MINUTE}. A lookup reserves its place before it starts (atomically), so many
 * requests sent at the same moment cannot all slip through before the first failures are counted.
 *
 * Only lookups count: a session found in the server's short cache never reaches this limiter, so signed-in
 * users behind the same address (an office network, the web app's proxy) keep working while someone there
 * sends made-up sessions; only their occasional fresh lookups wait until the minute is over.
 *
 * The address is the one Tomcat resolves from X-Forwarded-For (the rightmost entry that is not a trusted
 * proxy; see server.tomcat.remoteip in application.yml), which a caller cannot choose. Kept in memory per
 * server instance; Cloud Armor in front of the service gives a shared limit (DEPLOYMENT.md).
 */
@Component
public class FailedSessionLimiter {
    static final int MAX_FAILURES_PER_MINUTE = 30;
    private static final long WINDOW_MILLIS = 60_000;
    private static final int MAX_TRACKED_ADDRESSES = 50_000;

    private static final class Budget {
        final Deque<Long> failures = new ArrayDeque<>();
        int inFlight;
        void prune(long now) { while (!failures.isEmpty() && now - failures.peekFirst() >= WINDOW_MILLIS) failures.pollFirst(); }
    }

    // Bounded and evicted entry by entry (least recently used, or idle for two windows), never cleared wholesale.
    private final Cache<String, Budget> budgets = Caffeine.newBuilder()
            .maximumSize(MAX_TRACKED_ADDRESSES)
            .expireAfterAccess(Duration.ofMillis(2 * WINDOW_MILLIS))
            .build();

    /** A lookup gate for one request from this address (see {@link ClientSessionService.LookupGate}). */
    public ClientSessionService.LookupGate gateFor(String address) {
        String key = address == null || address.isBlank() ? "unknown" : address;
        return new ClientSessionService.LookupGate() {
            private boolean started;
            @Override public boolean tryBegin() {
                Budget budget = budgets.get(key, ignored -> new Budget());
                synchronized (budget) {
                    budget.prune(System.currentTimeMillis());
                    if (budget.failures.size() + budget.inFlight >= MAX_FAILURES_PER_MINUTE) return false;
                    budget.inFlight++;
                    started = true;
                    return true;
                }
            }
            @Override public void end(boolean failed) {
                if (!started) return;
                started = false;
                Budget budget = budgets.get(key, ignored -> new Budget());
                synchronized (budget) {
                    if (budget.inFlight > 0) budget.inFlight--;
                    long now = System.currentTimeMillis();
                    budget.prune(now);
                    if (failed && budget.failures.size() < MAX_FAILURES_PER_MINUTE) budget.failures.addLast(now);
                }
            }
        };
    }
}
