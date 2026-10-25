package dev.authsync.entry;

import dev.authsync.config.AuthSyncProperties;
import dev.authsync.config.OperationRateLimiter;
import dev.authsync.config.ReauthenticationRequiredException;
import dev.authsync.config.RecentSignInPolicy;
import jakarta.validation.Validator;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class EntryDeletionSecurityTest {
    private final Instant now = Instant.parse("2026-10-23T12:00:00Z");
    private final EntryService service = mock(EntryService.class);
    private final EntryController controller = new EntryController(service, mock(Validator.class), new OperationRateLimiter(),
            new RecentSignInPolicy(new AuthSyncProperties("web", "extension", ""), Clock.fixed(now, ZoneOffset.UTC)));

    @Test
    void neitherASessionNorAnOldGoogleTokenCanDeleteThroughEitherEndpoint() {
        UUID id = UUID.randomUUID();
        for (Jwt jwt : List.of(token(RecentSignInPolicy.SESSION_TOKEN_ALGORITHM, now), token("RS256", now.minusSeconds(600)))) {
            assertThatThrownBy(() -> controller.delete(jwt, id)).isInstanceOf(ReauthenticationRequiredException.class);
            assertThatThrownBy(() -> controller.batch(jwt, new EntryController.BatchRequest(List.of(
                    new EntryController.BatchOperation(" delete ", id, null, null)))))
                    .isInstanceOf(ReauthenticationRequiredException.class);
        }
        verifyNoInteractions(service);
    }

    @Test
    void aRecentGoogleTokenCanDeleteThroughBothEndpoints() {
        UUID id = UUID.randomUUID();
        Jwt jwt = token("RS256", now.minusSeconds(30));
        controller.delete(jwt, id);
        verify(service).delete(new AuthenticatedUser("user", null, null), id);
        when(service.applyBatch(any(), any())).thenReturn(new EntryService.BatchOutcome(1, null, null));
        controller.batch(jwt, new EntryController.BatchRequest(List.of(new EntryController.BatchOperation("DELETE", id, null, null))));
        verify(service).applyBatch(any(), eq(List.of(new EntryService.BatchChange(id, true, null))));
    }

    private Jwt token(String algorithm, Instant issuedAt) {
        return Jwt.withTokenValue("test").header("alg", algorithm).subject("user").issuedAt(issuedAt).expiresAt(now.plusSeconds(3600)).build();
    }
}
