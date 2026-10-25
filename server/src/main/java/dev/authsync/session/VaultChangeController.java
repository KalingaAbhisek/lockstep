package dev.authsync.session;

import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.ListenerRegistration;
import dev.authsync.config.OperationRateLimiter;
import jakarta.annotation.PreDestroy;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

/** Firestore-backed notifications work across API instances; no credentials or vault data enter the stream. */
@RestController
public class VaultChangeController {
    private static final int MAX_CONNECTIONS = 2000;
    private static final int MAX_PER_ACCOUNT = 4;
    private static final long LIFETIME_MILLIS = 240_000;
    private static final java.util.concurrent.atomic.AtomicLong SEQUENCE = new java.util.concurrent.atomic.AtomicLong();
    private final Firestore firestore;
    private final ScheduledExecutorService timer = Executors.newSingleThreadScheduledExecutor(
            Thread.ofPlatform().daemon().name("vault-events-timer").factory());
    private final ExecutorService sends = Executors.newVirtualThreadPerTaskExecutor();
    private final Set<Connection> connections = new HashSet<>();
    private final Map<String, Integer> counts = new HashMap<>();

    public VaultChangeController(Firestore firestore) { this.firestore = firestore; }

    @GetMapping(value = "/api/v1/events", produces = "text/event-stream")
    SseEmitter events(@AuthenticationPrincipal Jwt jwt, HttpServletRequest request, HttpServletResponse response) {
        String type = request.getHeader(ClientSessionValidationFilter.CLIENT_HEADER);
        if (!"web".equals(type) && !"extension".equals(type)) throw new IllegalArgumentException("Invalid client type");
        String token = ClientSessionValidationFilter.sessionToken(request);
        if (token == null || token.isBlank()) throw new IllegalArgumentException("A session is required");
        long lifetime = jwt.getExpiresAt() == null ? LIFETIME_MILLIS : Math.max(1,
                Math.min(LIFETIME_MILLIS, jwt.getExpiresAt().toEpochMilli() - System.currentTimeMillis()));
        var connection = new Connection(jwt.getSubject(), type, lifetime);
        reserve(connection);
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("X-Accel-Buffering", "no");
        connection.emitter.onCompletion(connection::close);
        connection.emitter.onTimeout(connection::close);
        connection.emitter.onError(ignored -> connection.close());
        try {
            var user = firestore.collection("users").document(jwt.getSubject());
            String expectedHash = hash(token);
            long generation = dev.authsync.entry.AuthenticatedUser.generation(jwt);
            // Watch the caller's session as well: sign-out, replacement and reset terminate the old stream.
            connection.add(user.collection("clientSessions").document(type).addSnapshotListener((snapshot, error) -> {
                if (error != null) { connection.close(); return; }
                if (snapshot == null || !snapshot.exists() || !expectedHash.equals(snapshot.getString("tokenHash"))
                        || (snapshot.contains("vaultGeneration") ? snapshot.getLong("vaultGeneration") : 0L) != generation) {
                    connection.offer(3); return;
                }
                var expires = snapshot.getTimestamp("expiresAt");
                if (expires == null) { connection.offer(3); return; }
                connection.expires.set(Instant.ofEpochSecond(expires.getSeconds(), expires.getNanos()));
                if (!connection.expires.get().isAfter(Instant.now())) connection.offer(3);
            }));
            // Includes the initial snapshot, which closes any gap while connecting/reconnecting.
            connection.add(user.addSnapshotListener((snapshot, error) -> {
                if (error != null) connection.close(); else connection.offer(2);
            }));
            var heartbeat = timer.scheduleAtFixedRate(() -> {
                Instant expires = connection.expires.get();
                connection.offer(expires != null && !expires.isAfter(Instant.now()) ? 3 : 1);
            }, 15, 15, TimeUnit.SECONDS);
            connection.add(() -> heartbeat.cancel(false));
            var expiry = timer.schedule(connection::close, lifetime, TimeUnit.MILLISECONDS);
            connection.add(() -> expiry.cancel(false));
        } catch (RuntimeException error) { connection.close(); throw error; }
        return connection.emitter;
    }

    /**
     * An account may hold MAX_PER_ACCOUNT connections. When it is full, the oldest connection of the same client
     * type (else the account's oldest) is closed to make room: it is usually one the client already left (a closed
     * popup or a reloaded page whose disconnect has not been noticed yet), and a client that is still there simply
     * reconnects. Refusing instead would shut the newest client out of live changes for the Retry-After minute.
     */
    private void reserve(Connection connection) {
        Connection evicted = null;
        synchronized (this) {
            if (counts.getOrDefault(connection.subject, 0) >= MAX_PER_ACCOUNT) {
                Connection sameType = null, any = null;
                for (Connection existing : connections) {
                    if (!existing.subject.equals(connection.subject)) continue;
                    if (any == null || existing.sequence < any.sequence) any = existing;
                    if (existing.type.equals(connection.type) && (sameType == null || existing.sequence < sameType.sequence)) sameType = existing;
                }
                evicted = sameType != null ? sameType : any;
                if (evicted != null) releaseLocked(evicted);
            }
            if (connections.size() >= MAX_CONNECTIONS || counts.getOrDefault(connection.subject, 0) >= MAX_PER_ACCOUNT)
                throw new OperationRateLimiter.RateLimitedException("Too many live connections. Close an unused Lockstep tab and try again.");
            connections.add(connection);
            counts.merge(connection.subject, 1, Integer::sum);
        }
        // Closed outside this monitor: Connection.close() takes the connection's lock and then this one.
        if (evicted != null) evicted.close();
    }

    private synchronized void release(Connection connection) { releaseLocked(connection); }

    private void releaseLocked(Connection connection) {
        if (connections.remove(connection)) {
            int remaining = counts.getOrDefault(connection.subject, 1) - 1;
            if (remaining == 0) counts.remove(connection.subject); else counts.put(connection.subject, remaining);
        }
    }

    static String hash(String token) {
        try { return Base64.getUrlEncoder().withoutPadding().encodeToString(
                MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8))); }
        catch (java.security.NoSuchAlgorithmException error) { throw new IllegalStateException(error); }
    }

    @PreDestroy
    void shutdown() {
        List<Connection> current;
        synchronized (this) { current = List.copyOf(connections); }
        current.forEach(Connection::close);
        timer.shutdownNow(); sends.shutdownNow();
    }

    private final class Connection {
        final String subject, type;
        final long sequence = SEQUENCE.incrementAndGet();
        final SseEmitter emitter;
        final AtomicBoolean closed = new AtomicBoolean(), sending = new AtomicBoolean();
        final AtomicInteger pending = new AtomicInteger();
        final AtomicReference<Instant> expires = new AtomicReference<>();
        final List<ListenerRegistration> cleanup = new ArrayList<>();
        Connection(String subject, String type, long lifetime) { this.subject = subject; this.type = type; emitter = new SseEmitter(lifetime); }
        synchronized void add(ListenerRegistration registration) {
            if (closed.get()) registration.remove(); else cleanup.add(registration);
        }
        void offer(int kind) {
            if (closed.get()) return;
            pending.accumulateAndGet(kind, Math::max);
            if (!sending.compareAndSet(false, true)) return;
            try { sends.execute(() -> {
                try {
                    int next;
                    while (!closed.get() && (next = pending.getAndSet(0)) != 0) {
                        if (next == 1) emitter.send(SseEmitter.event().comment("keepalive"));
                        else emitter.send(SseEmitter.event().name(next == 3 ? "session" : "change").data("{}"));
                        if (next == 3) { close(); break; }
                    }
                } catch (Exception error) { close(); }
                finally { sending.set(false); if (pending.get() != 0 && !closed.get()) offer(pending.get()); }
            }); } catch (RuntimeException error) { sending.set(false); close(); }
        }
        synchronized void close() {
            if (!closed.compareAndSet(false, true)) return;
            cleanup.forEach(ListenerRegistration::remove); cleanup.clear();
            release(this); emitter.complete();
        }
    }
}
