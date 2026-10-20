package dev.authsync.lock;

public record LockSettings(byte[] salt, byte[] verifier, int iterations, int timeoutSeconds, boolean lockOnScreenLock, WrappedVaultKey wrappedKey) {
    public LockSettings(byte[] salt, byte[] verifier, int iterations, int timeoutSeconds) {
        this(salt, verifier, iterations, timeoutSeconds, false, null);
    }
    public LockSettings(byte[] salt, byte[] verifier, int iterations, int timeoutSeconds, WrappedVaultKey wrappedKey) {
        this(salt, verifier, iterations, timeoutSeconds, false, wrappedKey);
    }
    public LockSettings {
        salt = salt.clone();
        verifier = verifier.clone();
    }
}
