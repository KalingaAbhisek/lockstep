package dev.authsync.config;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

/**
 * Destructive or key-changing requests (vault reset, recovery-key rotation, replacing the wrapped key,
 * signing out every device) need a Google ID token issued within the last few minutes. A copied 30-day
 * Lockstep session alone is not enough for them.
 */
@Component
public class RecentSignInPolicy {
    /** Header value the session filter gives tokens it builds from a Lockstep session (not from Google). */
    public static final String SESSION_TOKEN_ALGORITHM = "LOCKSTEP-SESSION";
    private final Duration maxAge;
    private final Clock clock;

    public RecentSignInPolicy(AuthSyncProperties properties, Clock clock) {
        this.maxAge = Duration.ofSeconds(Math.max(30, properties.reauthMaxAgeSeconds()));
        this.clock = clock;
    }

    public boolean isRecent(Jwt jwt) {
        if (jwt == null || SESSION_TOKEN_ALGORITHM.equals(jwt.getHeaders().get("alg"))) return false;
        Instant issuedAt = jwt.getIssuedAt();
        return issuedAt != null && !issuedAt.isBefore(clock.instant().minus(maxAge));
    }

    public void require(Jwt jwt) {
        if (!isRecent(jwt)) throw new ReauthenticationRequiredException();
    }
}
