package dev.authsync.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Arrays;
import java.util.List;

@ConfigurationProperties("authsync")
public class AuthSyncProperties {
    private String googleWebClientId;
    private String googleExtensionClientId;
    private String allowedOrigins;
    private String firebaseProjectId;
    private String firebaseCredentialsPath;

    public AuthSyncProperties() {}

    public AuthSyncProperties(String googleWebClientId,
                              String googleExtensionClientId, String allowedOrigins) {
        this.googleWebClientId = googleWebClientId;
        this.googleExtensionClientId = googleExtensionClientId;
        this.allowedOrigins = allowedOrigins;
    }

    public String googleWebClientId() { return googleWebClientId; }
    public String firebaseProjectId() { return firebaseProjectId; }
    public String firebaseCredentialsPath() { return firebaseCredentialsPath; }

    public List<String> googleClientIds() {
        return List.of(googleWebClientId, googleExtensionClientId).stream()
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
}

