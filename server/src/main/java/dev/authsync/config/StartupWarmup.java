package dev.authsync.config;

import com.google.cloud.firestore.Firestore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

/**
 * Pays the one-time setup costs right after startup instead of during the first user request:
 * opening the Firestore connection (plus its access token) and downloading Google's sign-in keys.
 * Runs in the background, never blocks startup, and ignores every failure.
 */
@Component
class StartupWarmup {
    private static final Logger log = LoggerFactory.getLogger(StartupWarmup.class);
    private final Firestore firestore;
    private final JwtDecoder jwtDecoder;

    StartupWarmup(Firestore firestore, JwtDecoder jwtDecoder) {
        this.firestore = firestore;
        this.jwtDecoder = jwtDecoder;
    }

    @EventListener(ApplicationReadyEvent.class)
    void warmUp() {
        Thread.ofVirtual().name("lockstep-warmup").start(() -> {
            long started = System.nanoTime();
            try {
                // Reads a document that never exists; it only opens the connection.
                firestore.collection("users").document("lockstep-warmup").get().get(15, TimeUnit.SECONDS);
            } catch (Exception exception) {
                if (exception instanceof InterruptedException) Thread.currentThread().interrupt();
                log.debug("Firestore warm-up failed", exception);
            }
            try {
                // A token with an unknown key ID makes the decoder download and cache Google's public keys.
                // It is always rejected; that is expected.
                jwtDecoder.decode(unsignedTokenWithUnknownKey());
            } catch (Exception expected) {
                log.debug("Sign-in key warm-up finished: {}", expected.getMessage());
            }
            log.info("Warm-up finished in {} ms", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started));
        });
    }

    private static String unsignedTokenWithUnknownKey() {
        Base64.Encoder encoder = Base64.getUrlEncoder().withoutPadding();
        String header = encoder.encodeToString("{\"alg\":\"RS256\",\"kid\":\"lockstep-warmup\",\"typ\":\"JWT\"}".getBytes(StandardCharsets.UTF_8));
        String payload = encoder.encodeToString("{\"sub\":\"lockstep-warmup\"}".getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + "." + encoder.encodeToString(new byte[]{0});
    }
}
