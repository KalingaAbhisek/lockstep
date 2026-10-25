package dev.authsync.lock;

/**
 * The vault master key, encrypted with a key derived from the user's passphrase. {@code wrapping} names the
 * derivation: "PBKDF2-SHA256/AES-256-GCM" ({@code iterations} rounds) or "ARGON2ID-V13/AES-256-GCM"
 * ({@code iterations} passes over {@code memoryKiB} of memory with {@code parallelism} lanes).
 */
public record WrappedVaultKey(
        int currentVersion,
        long createdAt,
        long wrappedAt,
        String wrapping,
        int iterations,
        String salt,
        String iv,
        String wrappedMasterKey,
        Integer memoryKiB,
        Integer parallelism
) {
    public WrappedVaultKey(int currentVersion, long createdAt, long wrappedAt, String wrapping, int iterations,
                           String salt, String iv, String wrappedMasterKey) {
        this(currentVersion, createdAt, wrappedAt, wrapping, iterations, salt, iv, wrappedMasterKey, null, null);
    }
}
