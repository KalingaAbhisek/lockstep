package dev.authsync.lock;

public record LockSettings(byte[] salt, byte[] verifier, int iterations, int timeoutSeconds, WrappedVaultKey wrappedKey) {
    public LockSettings(byte[] salt, byte[] verifier, int iterations, int timeoutSeconds) {
        this(salt, verifier, iterations, timeoutSeconds, null);
    }
    public LockSettings {
        salt = salt.clone();
        verifier = verifier.clone();
    }
}
