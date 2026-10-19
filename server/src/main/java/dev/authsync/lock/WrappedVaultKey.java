package dev.authsync.lock;

public record WrappedVaultKey(
        int currentVersion,
        long createdAt,
        long wrappedAt,
        String wrapping,
        int iterations,
        String salt,
        String iv,
        String wrappedMasterKey
) {}
