package dev.authsync.session;

public interface ClientSessionRepository {
    void replace(String googleSubject, ClientType clientType, String tokenHash);
    boolean matches(String googleSubject, ClientType clientType, String tokenHash);
}
