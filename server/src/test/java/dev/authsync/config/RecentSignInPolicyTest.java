package dev.authsync.config;

import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RecentSignInPolicyTest {
    private static final Instant NOW = Instant.parse("2026-10-22T12:00:00Z");
    private final RecentSignInPolicy policy = new RecentSignInPolicy(new AuthSyncProperties("web", "extension", ""), Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void aGoogleTokenFromTheLastFiveMinutesCounts() {
        assertThat(policy.isRecent(google(NOW.minusSeconds(60)))).isTrue();
        assertThat(policy.isRecent(google(NOW.minusSeconds(301)))).isFalse();
    }

    @Test
    void aLockstepSessionAloneNeverCounts() {
        Jwt session = Jwt.withTokenValue("session").header("alg", RecentSignInPolicy.SESSION_TOKEN_ALGORITHM)
                .subject("user").issuedAt(NOW).expiresAt(NOW.plusSeconds(60)).build();
        assertThat(policy.isRecent(session)).isFalse();
        assertThatThrownBy(() -> policy.require(session)).isInstanceOf(ReauthenticationRequiredException.class);
    }

    private static Jwt google(Instant issuedAt) {
        return Jwt.withTokenValue("google").header("alg", "RS256").subject("user").issuedAt(issuedAt).expiresAt(issuedAt.plusSeconds(3600)).build();
    }
}
