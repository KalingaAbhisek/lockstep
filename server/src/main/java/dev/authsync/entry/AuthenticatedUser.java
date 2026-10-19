package dev.authsync.entry;

/** Identity data taken from a verified Google ID token. */
public record AuthenticatedUser(String googleSubject, String email, String displayName) {
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
