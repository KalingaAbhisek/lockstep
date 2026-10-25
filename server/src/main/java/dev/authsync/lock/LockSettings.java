package dev.authsync.lock;

/**
 * Lock preferences synchronized between a user's devices. The passkey itself never reaches the server:
 * clients verify it locally by unwrapping {@code wrappedKey}.
 *
 * {@code legacySalt}, {@code legacyVerifier} and {@code legacyIterations} belong to an older design that
 * stored a server-side passkey verifier. They are only read so they can be deleted, and are null otherwise.
 */
public record LockSettings(int timeoutSeconds, boolean lockOnScreenLock, WrappedVaultKey wrappedKey,
                           byte[] legacySalt, byte[] legacyVerifier, Integer legacyIterations) {
    public LockSettings(int timeoutSeconds, boolean lockOnScreenLock, WrappedVaultKey wrappedKey) {
        this(timeoutSeconds, lockOnScreenLock, wrappedKey, null, null, null);
    }

    public LockSettings {
        legacySalt = legacySalt == null ? null : legacySalt.clone();
        legacyVerifier = legacyVerifier == null ? null : legacyVerifier.clone();
    }

    public boolean hasLegacyVerifier() {
        return legacySalt != null || legacyVerifier != null || legacyIterations != null;
    }
}
