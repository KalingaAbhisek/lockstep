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

class ClientSessionCacheTest {
    private final CountingRepository repository = new CountingRepository();
    private final ClientSessionService service = new ClientSessionService(repository, properties(30));

    @Test
    void repeatedValidationsReuseTheRememberedSession() {
        Jwt web = jwt("user-1");
        String token = service.register(web, "web").sessionToken();

        for (int request = 0; request < 5; request++) {
            assertThat(service.validate("user-1", "web", token).status()).isEqualTo(ClientSessionService.SessionStatus.ACTIVE);
        }
        assertThat(repository.reads).isZero();
    }

    @Test
    void aReplacedTokenIsRevokedImmediatelyOnTheSameServer() {
        Jwt web = jwt("user-1");
        String first = service.register(web, "web").sessionToken();
        String second = service.register(web, "web").sessionToken();

        assertThat(service.validate("user-1", "web", first).status()).isEqualTo(ClientSessionService.SessionStatus.REVOKED);
        assertThat(service.validate("user-1", "web", second).status()).isEqualTo(ClientSessionService.SessionStatus.ACTIVE);
    }

    @Test
    void aLoginOnAnotherServerIsSeenWhenTheTokenDoesNotMatchTheCache() {
        Jwt web = jwt("user-1");
        ClientSessionService otherServer = new ClientSessionService(repository, properties(30));
        String oldToken = service.register(web, "web").sessionToken();
        String newToken = otherServer.register(web, "web").sessionToken();

        // The new token is not in this server's cache, so Firestore is read and the new session is accepted.
        assertThat(service.validate("user-1", "web", newToken).status()).isEqualTo(ClientSessionService.SessionStatus.ACTIVE);
        assertThat(service.validate("user-1", "web", oldToken).status()).isEqualTo(ClientSessionService.SessionStatus.REVOKED);
    }

    @Test
    void highRiskRequestsIgnoreTheCacheAndSeeARevocationFromAnotherServer() {
        Jwt web = jwt("user-1");
        String token = service.register(web, "web").sessionToken();
        repository.sessions.clear(); // signed out of every device on another server instance

        // Ordinary requests may still use the cached copy for a few seconds...
        assertThat(service.validate("user-1", "web", token).status()).isEqualTo(ClientSessionService.SessionStatus.ACTIVE);
        // ...but a key rotation, reset or "sign out everywhere" reads the stored session.
        assertThat(service.validate("user-1", "web", token, true).status()).isEqualTo(ClientSessionService.SessionStatus.REVOKED);
    }

    @Test
    void forgettingASubjectReadsFirestoreAgain() {
        Jwt web = jwt("user-1");
        String token = service.register(web, "web").sessionToken();
        repository.sessions.clear(); // vault reset deleted the stored sessions

        service.forget("user-1");

        assertThat(service.validate("user-1", "web", token).status()).isEqualTo(ClientSessionService.SessionStatus.REVOKED);
    }

    @Test
    void serverSideSignOutRevokesTheTokenImmediately() {
        String web = service.register(jwt("user-1"), "web").sessionToken();
        String extension = service.register(jwt("user-1"), "extension").sessionToken();

        service.revoke("user-1", ClientType.WEB, false, web);

        assertThat(service.validate("user-1", "web", web).status()).isEqualTo(ClientSessionService.SessionStatus.REVOKED);
        assertThat(service.validate("user-1", "extension", extension).status()).isEqualTo(ClientSessionService.SessionStatus.ACTIVE);

        service.revoke("user-1", ClientType.EXTENSION, true, extension);
        assertThat(service.validate("user-1", "extension", extension).status()).isEqualTo(ClientSessionService.SessionStatus.REVOKED);
    }

    @Test
    void cachingCanBeDisabled() {
        ClientSessionService uncached = new ClientSessionService(repository, properties(0));
        String token = uncached.register(jwt("user-1"), "web").sessionToken();

        uncached.validate("user-1", "web", token);
        uncached.validate("user-1", "web", token);

        assertThat(repository.reads).isEqualTo(2);
    }

    private static AuthSyncProperties properties(int cacheSeconds) {
        AuthSyncProperties properties = new AuthSyncProperties("shared-client", "shared-client", "");
        properties.setSessionCacheSeconds(cacheSeconds);
        return properties;
    }

    private static Jwt jwt(String subject) {
        Instant now = Instant.now();
        return Jwt.withTokenValue("google-token").header("alg", "RS256").subject(subject)
                .audience(List.of("shared-client")).issuedAt(now).expiresAt(now.plusSeconds(3600)).build();
    }

    private static final class CountingRepository implements ClientSessionRepository {
        private final Map<String, StoredSession> sessions = new HashMap<>();
        private int reads;

        @Override
        public synchronized boolean revokeChecked(String subject, ClientType type, String hash, boolean all) {
            StoredSession caller = sessions.get(subject + ":" + type.value());
            if (caller == null || !caller.tokenHash().equals(hash)) return false;
            for (ClientType target : all ? ClientType.values() : new ClientType[]{type}) delete(subject, target);
            return true;
        }

        @Override
        public void replace(String googleSubject, ClientType clientType, StoredSession session) {
            sessions.put(googleSubject + ":" + clientType.value(), session);
        }

        @Override
        public void delete(String googleSubject, ClientType clientType) {
            sessions.remove(googleSubject + ":" + clientType.value());
        }

        @Override
        public Optional<StoredSession> find(String googleSubject, ClientType clientType) {
            reads++;
            return Optional.ofNullable(sessions.get(googleSubject + ":" + clientType.value()));
        }
    }
}
