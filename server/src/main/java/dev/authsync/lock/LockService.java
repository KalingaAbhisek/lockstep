package dev.authsync.lock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.Set;

/**
 * Synchronized lock preferences. The passkey is never sent to or stored on the server: each client
 * verifies it locally by unwrapping the synchronized wrapped vault key.
 */
@Service
public class LockService {
    private static final Logger log = LoggerFactory.getLogger(LockService.class);
    private static final int DEFAULT_TIMEOUT = 300;
    private static final Set<Integer> ALLOWED_TIMEOUTS = Set.of(
            300, 600, 900, 1200, 1500, 1800, 2100, 2400, 2700, 3000, 3300,
            3600, 7200, 14400, 28800, 43200, 86400, 172800, 604800);
    private final LockSettingsRepository repository;

    public LockService(LockSettingsRepository repository) { this.repository = repository; }

    public LockConfig config(String subject) {
        LockSettingsRepository.AccountLock account = repository.findAccount(subject);
        return toConfig(subject, account.settings(), account.revision());
    }

    /** Account existence and lock settings from a single lookup (used by the startup bootstrap). */
    public AccountState accountState(String subject) {
        LockSettingsRepository.AccountLock account = repository.findAccount(subject);
        return new AccountState(account.exists(), toConfig(subject, account.settings(), account.revision()));
    }

    private LockConfig toConfig(String subject, Optional<LockSettings> found, long revision) {
        found.filter(LockSettings::hasLegacyVerifier).ifPresent(settings -> removeLegacyVerifier(subject));
        return found.map(settings -> new LockConfig(true,
                ALLOWED_TIMEOUTS.contains(settings.timeoutSeconds()) ? settings.timeoutSeconds() : DEFAULT_TIMEOUT,
                settings.lockOnScreenLock(), settings.wrappedKey(), revision)).orElse(new LockConfig(false, 0, false, null, revision));
    }

    // Verifiers stored by older versions let anyone with database access guess the passkey offline,
    // so they are deleted the first time the account's lock settings are read.
    private void removeLegacyVerifier(String subject) {
        try { repository.deleteLegacyVerifier(subject); }
        catch (RuntimeException exception) { log.warn("Could not remove a legacy passkey verifier", exception); }
    }

    public LockConfig configure(String subject, int timeoutSeconds, boolean lockOnScreenLock, WrappedVaultKey wrappedKey) {
        return configure(subject, timeoutSeconds, lockOnScreenLock, wrappedKey, null, true);
    }

    /**
     * Saves lock settings. {@code expectedRevision} is the vault revision the client last saw; when given,
     * the save is refused (409) if another device changed the wrapped key since. Older clients send none.
     */
    public LockConfig configure(String subject, int timeoutSeconds, boolean lockOnScreenLock, WrappedVaultKey wrappedKey,
                                Long expectedRevision, boolean recentSignIn) {
        return configure(subject, timeoutSeconds, lockOnScreenLock, wrappedKey, expectedRevision, recentSignIn, null);
    }

    public LockConfig configure(String subject, int timeoutSeconds, boolean lockOnScreenLock, WrappedVaultKey wrappedKey,
                                Long expectedRevision, boolean recentSignIn, Long expectedGeneration) {
        requireAllowedTimeout(timeoutSeconds);
        validateWrappedKey(wrappedKey);
        long revision = repository.saveChecked(subject, new LockSettings(timeoutSeconds, lockOnScreenLock, wrappedKey), expectedRevision, recentSignIn, expectedGeneration);
        return new LockConfig(true, timeoutSeconds, lockOnScreenLock, wrappedKey, revision);
    }

    public void remove(String subject) { repository.delete(subject); }

    public static void requireAllowedTimeout(int timeoutSeconds) {
        if (!ALLOWED_TIMEOUTS.contains(timeoutSeconds)) throw new IllegalArgumentException("Unsupported lock timeout");
    }

    public static final String PBKDF2_WRAPPING = "PBKDF2-SHA256/AES-256-GCM";
    public static final String ARGON2ID_WRAPPING = "ARGON2ID-V13/AES-256-GCM";

    public static void validateWrappedKey(WrappedVaultKey key) {
        if (key == null) return; // Legacy clients are migrated when they next change or restore their passkey.
        boolean common = key.currentVersion() >= 1 && key.currentVersion() <= 1_000_000 && key.createdAt() >= 1 && key.wrappedAt() >= 1
                && base64(key.salt(), 24) && base64(key.iv(), 16) && base64(key.wrappedMasterKey(), 64);
        boolean pbkdf2 = PBKDF2_WRAPPING.equals(key.wrapping()) && key.iterations() == 600_000
                && key.memoryKiB() == null && key.parallelism() == null;
        // Argon2id: at least OWASP's minimum (19 MiB, 2 passes) and at most what a browser tab can afford.
        boolean argon2id = ARGON2ID_WRAPPING.equals(key.wrapping()) && key.iterations() >= 2 && key.iterations() <= 10
                && key.memoryKiB() != null && key.memoryKiB() >= 19_456 && key.memoryKiB() <= 262_144
                && key.parallelism() != null && key.parallelism() >= 1 && key.parallelism() <= 4;
        if (!common || !(pbkdf2 || argon2id)) throw new IllegalArgumentException("Invalid wrapped vault key metadata");
    }

    private static boolean base64(String value, int length) {
        return value != null && value.length() == length && value.matches("[A-Za-z0-9+/]+={0,2}");
    }

    /** {@code vaultRevision}: server-side counter that changes whenever the wrapped key changes (see saveChecked). */
    public record LockConfig(boolean enabled, int timeoutSeconds, boolean lockOnScreenLock, WrappedVaultKey wrappedKey, long vaultRevision) {
        public LockConfig(boolean enabled, int timeoutSeconds, boolean lockOnScreenLock, WrappedVaultKey wrappedKey) {
            this(enabled, timeoutSeconds, lockOnScreenLock, wrappedKey, 0);
        }
        public LockConfig(boolean enabled, int timeoutSeconds) { this(enabled, timeoutSeconds, false, null, 0); }
    }

    public record AccountState(boolean exists, LockConfig lock) {}
}
