package dev.authsync.entry;

/** Verified identity plus the vault generation bound to the validated server-side session. */
public record AuthenticatedUser(String googleSubject, String email, String displayName, long vaultGeneration) {
    public AuthenticatedUser(String subject, String email, String name) { this(subject, email, name, 0); }
    public static final String GENERATION_CLAIM = "lockstep_vault_generation";
    public static long generation(org.springframework.security.oauth2.jwt.Jwt jwt) {
        Number generation = jwt.getClaim(GENERATION_CLAIM);
        return generation == null ? 0 : generation.longValue();
    }
    public AuthenticatedUser {
        if (googleSubject == null || googleSubject.isBlank()) {
            throw new IllegalArgumentException("Google subject is required");
        }
        email = blankToNull(email);
        displayName = blankToNull(displayName);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.trim();
    }
}
