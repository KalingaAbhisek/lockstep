package dev.authsync.session;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
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
    private static final int MAX_CACHED_SESSIONS = 10_000;
    private final SecureRandom secureRandom = new SecureRandom();
    // Recently validated sessions, so most API requests skip the Firestore session read. Only sessions
    // that exist are cached; the token hash and expiry are still checked on every request. Bounded and
    // evicted entry by entry (no full clears), and null when caching is turned off.
    private final Cache<String, ClientSessionRepository.StoredSession> cache;
    // Account + token pairs that recently failed, so repeating a wrong or made-up token does not cost another
    // Firestore read. Safe to remember: tokens are random and never become valid later (a new sign-in issues
    // a new token). Bounded and evicted entry by entry.
    static final Duration FAILED_PAIR_LIFETIME = Duration.ofMinutes(1);
    private static final int MAX_FAILED_PAIRS = 50_000;
    private final Cache<String, Boolean> failedPairs = Caffeine.newBuilder()
            .maximumSize(MAX_FAILED_PAIRS).expireAfterWrite(FAILED_PAIR_LIFETIME).build();
    /** Session tokens issued by {@link #register}: 32 random bytes, Base64url without padding. */
    private static final java.util.regex.Pattern TOKEN_FORMAT = java.util.regex.Pattern.compile("[A-Za-z0-9_-]{43}");
    /** Google account IDs are at most 255 characters; anything longer cannot belong to a session. */
    static final int MAX_SUBJECT_LENGTH = 255;

    public ClientSessionService(ClientSessionRepository repository, AuthSyncProperties properties) {
        this.repository = repository;
        this.properties = properties;
        Duration cacheLifetime = Duration.ofSeconds(Math.max(0, properties.sessionCacheSeconds()));
        this.cache = cacheLifetime.isZero() ? null
                : Caffeine.newBuilder().maximumSize(MAX_CACHED_SESSIONS).expireAfterWrite(cacheLifetime).build();
    }

    public RegisteredSession register(Jwt jwt, String requestedClientType) {
        ClientType clientType = clientType(jwt, requestedClientType);
        byte[] random = new byte[32];
        secureRandom.nextBytes(random);
        String sessionToken = Base64.getUrlEncoder().withoutPadding().encodeToString(random);
        Instant expiresAt=Instant.now().plus(SESSION_LIFETIME);
        ClientSessionRepository.StoredSession stored = new ClientSessionRepository.StoredSession(
                hash(sessionToken),value(jwt.getClaimAsString("email")),value(jwt.getClaimAsString("name")),expiresAt);
        stored = repository.replaceChecked(jwt.getSubject(), clientType, stored);
        remember(jwt.getSubject(), clientType, stored);
        return new RegisteredSession(sessionToken, clientType.value(),expiresAt.toEpochMilli());
    }

    public boolean isActive(Jwt jwt, String requestedClientType, String sessionToken) {
        return validate(jwt,requestedClientType,sessionToken).status()==SessionStatus.ACTIVE;
    }

    public Optional<SessionPrincipal> authenticate(String subject,String requestedClientType,String sessionToken){
        return validate(subject,requestedClientType,sessionToken).principal();
    }

    public SessionValidation validate(Jwt jwt,String requestedClientType,String sessionToken){
        return validate(jwt,requestedClientType,sessionToken,false);
    }

    public SessionValidation validate(String subject,String requestedClientType,String sessionToken){
        return validate(subject,requestedClientType,sessionToken,false);
    }

    /** {@code fresh}: skip the in-memory cache and read the stored session (used for high-risk requests). */
    public SessionValidation validate(Jwt jwt,String requestedClientType,String sessionToken,boolean fresh){
        return validate(jwt.getSubject(),clientType(jwt,requestedClientType),sessionToken,fresh);
    }

    public SessionValidation validate(String subject,String requestedClientType,String sessionToken,boolean fresh){
        return validate(subject,parseClientType(requestedClientType),sessionToken,fresh,LookupGate.OPEN);
    }

    /** As above; {@code gate} decides whether a Firestore lookup may start (see FailedSessionLimiter). */
    public SessionValidation validate(Jwt jwt,String requestedClientType,String sessionToken,boolean fresh,LookupGate gate){
        return validate(jwt.getSubject(),clientType(jwt,requestedClientType),sessionToken,fresh,gate);
    }

    public SessionValidation validate(String subject,String requestedClientType,String sessionToken,boolean fresh,LookupGate gate){
        return validate(subject,parseClientType(requestedClientType),sessionToken,fresh,gate);
    }

    /**
     * Permission for one Firestore session lookup. {@link #tryBegin} is called right before the lookup and
     * may refuse it; {@link #end} follows every started lookup and says whether the session was refused.
     */
    public interface LookupGate {
        boolean tryBegin();
        void end(boolean failed);
        LookupGate OPEN = new LookupGate() {
            @Override public boolean tryBegin() { return true; }
            @Override public void end(boolean failed) {}
        };
    }

    private SessionValidation validate(String subject,ClientType clientType,String sessionToken,boolean fresh){
        return validate(subject,clientType,sessionToken,fresh,LookupGate.OPEN);
    }

    private SessionValidation validate(String subject,ClientType clientType,String sessionToken,boolean fresh,LookupGate gate){
        if(!isUsableSubject(subject)||sessionToken==null
                ||!TOKEN_FORMAT.matcher(sessionToken).matches())return SessionValidation.revoked(); // never read
        String tokenHash=hash(sessionToken);
        String pair=cacheKey(subject,clientType)+"\n"+tokenHash;
        if(failedPairs.getIfPresent(pair)!=null)return SessionValidation.revoked();
        // A session revoked on another server instance stays in this instance's cache for a few seconds;
        // fresh validation closes that window for requests that rotate keys, reset or sign out everywhere.
        ClientSessionRepository.StoredSession stored=fresh?null:cachedMatch(subject,clientType,tokenHash);
        if(stored==null){
            // Not cached, or cached for a different token: read the authoritative copy from Firestore, if
            // this client address still has lookups left (see FailedSessionLimiter).
            if(!gate.tryBegin())return SessionValidation.limited();
            boolean refused=false;
            try{
                Optional<ClientSessionRepository.StoredSession> found=repository.find(subject,clientType);
                if(found.isEmpty()){invalidate(subject,clientType);failedPairs.put(pair,Boolean.TRUE);refused=true;return SessionValidation.revoked();}
                stored=found.get();
                remember(subject,clientType,stored);
                refused=!MessageDigest.isEqual(stored.tokenHash().getBytes(StandardCharsets.UTF_8),tokenHash.getBytes(StandardCharsets.UTF_8));
            }finally{
                gate.end(refused);
            }
        }
        if(!MessageDigest.isEqual(stored.tokenHash().getBytes(StandardCharsets.UTF_8),tokenHash.getBytes(StandardCharsets.UTF_8))){
            failedPairs.put(pair,Boolean.TRUE);
            return SessionValidation.revoked();
        }
        if(!stored.expiresAt().isAfter(Instant.now()))return SessionValidation.expired();
        return SessionValidation.active(new SessionPrincipal(subject,stored.email(),stored.displayName(),stored.expiresAt(),clientType,stored.vaultGeneration()));
    }

    /**
     * A session-only request names its account in the X-Lockstep-Subject header, and that value becomes part of
     * Firestore document paths. Only values that are a single, ordinary document ID are looked up: a "/" would
     * address a different (nested) document, and ".", ".." and "__name__" IDs are reserved by Firestore. Google
     * account IDs are short digit strings, so no real subject is refused.
     */
    static boolean isUsableSubject(String subject) {
        return subject != null && !subject.isBlank() && subject.length() <= MAX_SUBJECT_LENGTH
                && subject.indexOf('/') < 0 && !subject.equals(".") && !subject.equals("..")
                && !(subject.startsWith("__") && subject.endsWith("__"))
                && subject.chars().noneMatch(character -> character < 0x20 || character == 0x7f);
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

    /** Drops remembered sessions for a subject whose server data was deleted (vault reset). */
    public void forget(String subject){
        if(subject==null)return;
        for(ClientType clientType:ClientType.values())invalidate(subject,clientType);
    }

    /**
     * Server-side sign-out: deletes the stored session for this client (or for both clients when
     * {@code allClients}). A copied session token stops working at once on this server instance, on other
     * instances within {@code SESSION_CACHE_SECONDS} (5 s by default), and at once everywhere for the
     * high-risk requests that always read the stored session.
     */
    public boolean revoke(String subject, ClientType clientType, boolean allClients, String sessionToken) {
        if (!isUsableSubject(subject) || sessionToken == null || !TOKEN_FORMAT.matcher(sessionToken).matches()) return false;
        boolean revoked = repository.revokeChecked(subject, clientType, hash(sessionToken), allClients);
        // Invalidating a newer cache entry is harmless: the next request reads its authoritative session.
        for (ClientType type : allClients ? ClientType.values() : new ClientType[]{clientType}) invalidate(subject, type);
        return revoked;
    }

    private void invalidate(String subject,ClientType clientType){
        if(cache!=null)cache.invalidate(cacheKey(subject,clientType));
    }

    private ClientSessionRepository.StoredSession cachedMatch(String subject,ClientType clientType,String tokenHash){
        if(cache==null)return null;
        ClientSessionRepository.StoredSession cached=cache.getIfPresent(cacheKey(subject,clientType));
        if(cached==null)return null;
        return MessageDigest.isEqual(cached.tokenHash().getBytes(StandardCharsets.UTF_8),tokenHash.getBytes(StandardCharsets.UTF_8))
                ? cached : null;
    }

    private void remember(String subject,ClientType clientType,ClientSessionRepository.StoredSession session){
        if(cache!=null)cache.put(cacheKey(subject,clientType),session);
    }

    private static String cacheKey(String subject,ClientType clientType){return clientType.value()+"\n"+subject;}

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
    public record SessionPrincipal(String subject,String email,String displayName,Instant expiresAt,ClientType clientType,long vaultGeneration) {}
    public enum SessionStatus { ACTIVE, EXPIRED, REVOKED, RATE_LIMITED }
    public record SessionValidation(SessionStatus status,Optional<SessionPrincipal> principal) {
        static SessionValidation active(SessionPrincipal principal){return new SessionValidation(SessionStatus.ACTIVE,Optional.of(principal));}
        static SessionValidation expired(){return new SessionValidation(SessionStatus.EXPIRED,Optional.empty());}
        static SessionValidation revoked(){return new SessionValidation(SessionStatus.REVOKED,Optional.empty());}
        static SessionValidation limited(){return new SessionValidation(SessionStatus.RATE_LIMITED,Optional.empty());}
    }
}
