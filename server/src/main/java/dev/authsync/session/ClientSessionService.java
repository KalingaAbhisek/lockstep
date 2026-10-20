package dev.authsync.session;

import dev.authsync.config.AuthSyncProperties;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;

@Service
public class ClientSessionService {
    public static final Duration SESSION_LIFETIME = Duration.ofDays(30);
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
        Instant expiresAt=Instant.now().plus(SESSION_LIFETIME);
        repository.replace(jwt.getSubject(), clientType, new ClientSessionRepository.StoredSession(
                hash(sessionToken),value(jwt.getClaimAsString("email")),value(jwt.getClaimAsString("name")),expiresAt));
        return new RegisteredSession(sessionToken, clientType.value(),expiresAt.toEpochMilli());
    }

    public boolean isActive(Jwt jwt, String requestedClientType, String sessionToken) {
        return validate(jwt,requestedClientType,sessionToken).status()==SessionStatus.ACTIVE;
    }

    public Optional<SessionPrincipal> authenticate(String subject,String requestedClientType,String sessionToken){
        return validate(subject,requestedClientType,sessionToken).principal();
    }

    public SessionValidation validate(Jwt jwt,String requestedClientType,String sessionToken){
        return validate(jwt.getSubject(),clientType(jwt,requestedClientType),sessionToken);
    }

    public SessionValidation validate(String subject,String requestedClientType,String sessionToken){
        return validate(subject,parseClientType(requestedClientType),sessionToken);
    }

    private SessionValidation validate(String subject,ClientType clientType,String sessionToken){
        if(subject==null||subject.isBlank()||sessionToken==null||sessionToken.isBlank())return SessionValidation.revoked();
        Optional<ClientSessionRepository.StoredSession> found=repository.find(subject,clientType);
        if(found.isEmpty())return SessionValidation.revoked();
        ClientSessionRepository.StoredSession stored=found.get();
        if(!MessageDigest.isEqual(stored.tokenHash().getBytes(StandardCharsets.UTF_8),hash(sessionToken).getBytes(StandardCharsets.UTF_8)))return SessionValidation.revoked();
        if(!stored.expiresAt().isAfter(Instant.now()))return SessionValidation.expired();
        return SessionValidation.active(new SessionPrincipal(subject,stored.email(),stored.displayName(),stored.expiresAt(),clientType));
    }

    public ClientType clientType(Jwt jwt, String requestedClientType) {
        ClientType clientType=parseClientType(requestedClientType);
        String expectedAudience = clientType == ClientType.WEB
                ? properties.googleWebClientId() : properties.googleExtensionClientId();
        if (!contains(jwt, expectedAudience)) throw new IllegalArgumentException("The Google token is not valid for this Lockstep client");
        return clientType;
    }

    public ClientType parseClientType(String requestedClientType){
        try{return ClientType.valueOf(String.valueOf(requestedClientType).trim().toUpperCase());}
        catch(IllegalArgumentException exception){throw new IllegalArgumentException("A valid Lockstep client type is required");}
    }

    private static String value(String value){return value==null?"":value;}

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

    public record RegisteredSession(String sessionToken, String clientType,long expiresAtEpochMillis) {}
    public record SessionPrincipal(String subject,String email,String displayName,Instant expiresAt,ClientType clientType) {}
    public enum SessionStatus { ACTIVE, EXPIRED, REVOKED }
    public record SessionValidation(SessionStatus status,Optional<SessionPrincipal> principal) {
        static SessionValidation active(SessionPrincipal principal){return new SessionValidation(SessionStatus.ACTIVE,Optional.of(principal));}
        static SessionValidation expired(){return new SessionValidation(SessionStatus.EXPIRED,Optional.empty());}
        static SessionValidation revoked(){return new SessionValidation(SessionStatus.REVOKED,Optional.empty());}
    }
}
