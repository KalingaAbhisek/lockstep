package dev.authsync.session;

import dev.authsync.config.AuthSyncProperties;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

@Service
public class ClientSessionService {
    private final ClientSessionRepository repository;
    private final AuthSyncProperties properties;
    private final SecureRandom secureRandom = new SecureRandom();

    public ClientSessionService(ClientSessionRepository repository, AuthSyncProperties properties) {
        this.repository = repository;
        this.properties = properties;
    }

    public RegisteredSession register(Jwt jwt, String requestedClientType) {
        ClientType clientType = clientType(jwt, requestedClientType);
        byte[] random = new byte[32];
        secureRandom.nextBytes(random);
        String sessionToken = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        repository.replace(jwt.getSubject(), clientType, hash(sessionToken));
        return new RegisteredSession(sessionToken, clientType.value());
    }

    public boolean isActive(Jwt jwt, String requestedClientType, String sessionToken) {
        return sessionToken != null && !sessionToken.isBlank()
                && repository.matches(jwt.getSubject(), clientType(jwt, requestedClientType), hash(sessionToken));
    }

    public ClientType clientType(Jwt jwt, String requestedClientType) {
        ClientType clientType;
        try { clientType = ClientType.valueOf(String.valueOf(requestedClientType).trim().toUpperCase()); }
        catch (IllegalArgumentException exception) { throw new IllegalArgumentException("A valid Lockstep client type is required"); }
        String expectedAudience = clientType == ClientType.WEB
                ? properties.googleWebClientId() : properties.googleExtensionClientId();
        if (!contains(jwt, expectedAudience)) throw new IllegalArgumentException("The Google token is not valid for this Lockstep client");
        return clientType;
    }

    private static boolean contains(Jwt jwt, String audience) {
        return audience != null && !audience.isBlank() && jwt.getAudience().contains(audience);
    }

    private static String hash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (NoSuchAlgorithmException exception) {
            throw new IllegalStateException("SHA-256 is unavailable", exception);
        }
    }

    public record RegisteredSession(String sessionToken, String clientType) {}
}
