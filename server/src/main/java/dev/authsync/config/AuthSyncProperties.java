package dev.authsync.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

@ConfigurationProperties("authsync")
public class AuthSyncProperties {
    private String googleWebClientId;
    private String googleExtensionClientId;
    private String allowedOrigins;
    private String firebaseProjectId;
    private String firebaseCredentialsPath;
    /** Seconds a validated client session is remembered in memory. 0 checks Firestore on every request. */
    private int sessionCacheSeconds;
    /** Extra public path the API is also served under (Firebase Hosting rewrite), e.g. "/lockstep". Empty turns it off. */
    private String publicPathPrefix = "/lockstep";
    /** How old a Google sign-in may be for reset, rotation, passphrase replacement and signing out everywhere. */
    private int reauthMaxAgeSeconds = 300;
    /** When true (default), changing an existing wrapped key requires the vault revision. */
    private boolean requireVaultRevision = true;
    /** When true (default), clients wrap the vault key with Argon2id instead of PBKDF2. */
    private boolean argon2idWrapping = true;
    /** When true (default), an update of an existing entry must carry baseMutationId. */
    private boolean requireEditBase = true;

    public AuthSyncProperties() {}

    public AuthSyncProperties(String googleWebClientId,
                              String googleExtensionClientId, String allowedOrigins) {
        this.googleWebClientId = googleWebClientId;
        this.googleExtensionClientId = googleExtensionClientId;
        this.allowedOrigins = allowedOrigins;
    }

    public String googleWebClientId() { return googleWebClientId; }
    public String googleExtensionClientId() { return googleExtensionClientId; }
    public String firebaseProjectId() { return firebaseProjectId; }
    public String firebaseCredentialsPath() { return firebaseCredentialsPath; }
    public int sessionCacheSeconds() { return sessionCacheSeconds; }
    public String publicPathPrefix() { return publicPathPrefix; }
    public int reauthMaxAgeSeconds() { return reauthMaxAgeSeconds; }
    public boolean requireVaultRevision() { return requireVaultRevision; }
    public boolean argon2idWrapping() { return argon2idWrapping; }
    public boolean requireEditBase() { return requireEditBase; }

    public List<String> googleClientIds() {
        return Stream.of(googleWebClientId, googleExtensionClientId)
                .filter(value -> value != null && !value.isBlank())
                .toList();
    }

    public List<String> allowedOriginList() {
        if (allowedOrigins == null || allowedOrigins.isBlank()) return List.of();
        return Arrays.stream(allowedOrigins.split(","))
                .map(String::trim)
                .filter(value -> !value.isBlank())
                .toList();
    }

    public void setGoogleWebClientId(String googleWebClientId) { this.googleWebClientId = googleWebClientId; }
    public void setGoogleExtensionClientId(String googleExtensionClientId) { this.googleExtensionClientId = googleExtensionClientId; }
    public void setAllowedOrigins(String allowedOrigins) { this.allowedOrigins = allowedOrigins; }
    public void setFirebaseProjectId(String firebaseProjectId) { this.firebaseProjectId = firebaseProjectId; }
    public void setFirebaseCredentialsPath(String firebaseCredentialsPath) { this.firebaseCredentialsPath = firebaseCredentialsPath; }
    public void setSessionCacheSeconds(int sessionCacheSeconds) { this.sessionCacheSeconds = Math.max(0, sessionCacheSeconds); }
    public void setPublicPathPrefix(String publicPathPrefix) { this.publicPathPrefix = publicPathPrefix; }
    public void setReauthMaxAgeSeconds(int reauthMaxAgeSeconds) { this.reauthMaxAgeSeconds = reauthMaxAgeSeconds; }
    public void setRequireVaultRevision(boolean requireVaultRevision) { this.requireVaultRevision = requireVaultRevision; }
    public void setArgon2idWrapping(boolean argon2idWrapping) { this.argon2idWrapping = argon2idWrapping; }
    public void setRequireEditBase(boolean requireEditBase) { this.requireEditBase = requireEditBase; }
}

