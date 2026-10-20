package dev.authsync.session;

import java.time.Instant;
import java.util.Optional;

public interface ClientSessionRepository {
    void replace(String googleSubject, ClientType clientType, StoredSession session);
    Optional<StoredSession> find(String googleSubject, ClientType clientType);

    record StoredSession(String tokenHash, String email, String displayName, Instant expiresAt) {}
}
