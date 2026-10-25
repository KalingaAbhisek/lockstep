package dev.authsync.session;

import java.time.Instant;
import java.util.Optional;

public interface ClientSessionRepository {
    void replace(String googleSubject, ClientType clientType, StoredSession session);
    /** Production adapters must atomically check reset state and bind the session to its vault generation. */
    default StoredSession replaceChecked(String subject, ClientType type, StoredSession session) {
        replace(subject, type, session); return session;
    }
    Optional<StoredSession> find(String googleSubject, ClientType clientType);
    /** Compare the caller's session and delete the requested sessions in one transaction. */
    default boolean revokeChecked(String subject, ClientType type, String expectedHash, boolean all) {
        throw new UnsupportedOperationException("Atomic session revocation is not supported by this repository");
    }
    /** Deletes the stored session (server-side sign-out). */
    default void delete(String googleSubject, ClientType clientType) {
        throw new UnsupportedOperationException("Session deletion is not supported by this repository");
    }

    record StoredSession(String tokenHash, String email, String displayName, Instant expiresAt, long vaultGeneration) {
        public StoredSession(String hash, String email, String name, Instant expires) { this(hash, email, name, expires, 0); }
    }
}
