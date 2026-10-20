package dev.authsync.session;

import dev.authsync.config.AuthSyncProperties;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class ClientSessionServiceTest {
    private final InMemoryRepository repository = new InMemoryRepository();
    private final ClientSessionService service = new ClientSessionService(
            repository, new AuthSyncProperties("shared-client", "shared-client", ""));

    @Test
    void aNewWebLoginReplacesThePreviousWebDevice() {
        Jwt web = jwt("user-1", "shared-client");

        String first = service.register(web, "web").sessionToken();
        String second = service.register(web, "web").sessionToken();

        assertThat(service.isActive(web, "web", first)).isFalse();
        assertThat(service.isActive(web, "web", second)).isTrue();
    }

    @Test
    void webAndExtensionSessionsRemainIndependent() {
        Jwt web = jwt("user-1", "shared-client");
        Jwt extension = jwt("user-1", "shared-client");

        String webToken = service.register(web, "web").sessionToken();
        String extensionToken = service.register(extension, "extension").sessionToken();

        assertThat(service.isActive(web, "web", webToken)).isTrue();
        assertThat(service.isActive(extension, "extension", extensionToken)).isTrue();
        assertThat(service.register(web, "web").clientType()).isEqualTo("web");
        assertThat(service.isActive(extension, "extension", extensionToken)).isTrue();
    }

    @Test
    void sessionExpiresThirtyDaysAfterGoogleSignIn() {
        Jwt web=jwt("user-1","shared-client");
        ClientSessionService.RegisteredSession registered=service.register(web,"web");

        assertThat(registered.expiresAtEpochMillis()).isBetween(
                Instant.now().plus(ClientSessionService.SESSION_LIFETIME).minusSeconds(5).toEpochMilli(),
                Instant.now().plus(ClientSessionService.SESSION_LIFETIME).plusSeconds(5).toEpochMilli());
        repository.expire("user-1",ClientType.WEB);
        assertThat(service.isActive(web,"web",registered.sessionToken())).isFalse();
        assertThat(service.validate(web,"web",registered.sessionToken()).status())
                .isEqualTo(ClientSessionService.SessionStatus.EXPIRED);
        assertThat(service.validate(web,"web","a-replaced-token").status())
                .isEqualTo(ClientSessionService.SessionStatus.REVOKED);
    }

    @Test
    void signingInAgainAfterExpiryCreatesAWorkingReplacementSession() {
        Jwt web=jwt("user-1","shared-client");
        ClientSessionService.RegisteredSession expired=service.register(web,"web");
        repository.expire("user-1",ClientType.WEB);

        ClientSessionService.RegisteredSession replacement=service.register(web,"web");

        assertThat(service.validate(web,"web",expired.sessionToken()).status())
                .isEqualTo(ClientSessionService.SessionStatus.REVOKED);
        assertThat(service.validate(web,"web",replacement.sessionToken()).status())
                .isEqualTo(ClientSessionService.SessionStatus.ACTIVE);
        assertThat(replacement.expiresAtEpochMillis()).isGreaterThan(Instant.now().plusSeconds(29L*24*60*60).toEpochMilli());
    }

    private static Jwt jwt(String subject, String audience) {
        Instant now = Instant.now();
        return Jwt.withTokenValue("google-token")
                .header("alg", "RS256")
                .subject(subject)
                .audience(List.of(audience))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(3600))
                .build();
    }

    private static final class InMemoryRepository implements ClientSessionRepository {
        @Override
        public void replace(String googleSubject, ClientType clientType, StoredSession session) {
            sessions.put(googleSubject + ":" + clientType.value(), session);
        }

        @Override
        public Optional<StoredSession> find(String googleSubject, ClientType clientType) {
            return Optional.ofNullable(sessions.get(googleSubject + ":" + clientType.value()));
        }

        void expire(String googleSubject,ClientType clientType){
            String key=googleSubject+":"+clientType.value();
            StoredSession current=sessions.get(key);
            sessions.put(key,new StoredSession(current.tokenHash(),current.email(),current.displayName(),Instant.now().minusSeconds(1)));
        }

        private final Map<String, StoredSession> sessions = new HashMap<>();
    }
}
