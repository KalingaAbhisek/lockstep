package dev.authsync.session;

import dev.authsync.config.AuthSyncProperties;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
        private final Map<String, String> sessions = new HashMap<>();

        @Override
        public void replace(String googleSubject, ClientType clientType, String tokenHash) {
            sessions.put(googleSubject + ":" + clientType.value(), tokenHash);
        }

        @Override
        public boolean matches(String googleSubject, ClientType clientType, String tokenHash) {
            return tokenHash.equals(sessions.get(googleSubject + ":" + clientType.value()));
        }
    }
}
