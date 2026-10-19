package dev.authsync.lock;

import org.springframework.stereotype.Service;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Set;

@Service
public class LockService {
    private static final int ITERATIONS = 210_000;
    private static final int KEY_BITS = 256;
    private static final Set<Integer> ALLOWED_TIMEOUTS = Set.of(60, 300, 900, 1800);
    private final LockSettingsRepository repository;
    private final SecureRandom random = new SecureRandom();

    public LockService(LockSettingsRepository repository) { this.repository = repository; }

    public LockConfig config(String subject) {
        return repository.find(subject).map(settings -> new LockConfig(true, Math.max(60, Math.min(settings.timeoutSeconds(), 1800)), settings.wrappedKey())).orElse(new LockConfig(false, 0, null));
    }

    public LockConfig configure(String subject, String passcode, int timeoutSeconds) {
        return configure(subject, passcode, timeoutSeconds, null);
    }

    public LockConfig configure(String subject, String passcode, int timeoutSeconds, WrappedVaultKey wrappedKey) {
        if (passcode == null || passcode.length() < 4 || passcode.length() > 128) throw new IllegalArgumentException("Passkey must contain 4 to 128 characters");
        if (!ALLOWED_TIMEOUTS.contains(timeoutSeconds)) throw new IllegalArgumentException("Unsupported lock timeout");
        validateWrappedKey(wrappedKey);
        byte[] salt = new byte[16]; random.nextBytes(salt);
        repository.save(subject, new LockSettings(salt, derive(passcode, salt, ITERATIONS), ITERATIONS, timeoutSeconds, wrappedKey));
        return new LockConfig(true, timeoutSeconds, wrappedKey);
    }

    public boolean verify(String subject, String passcode) {
        return repository.find(subject).map(settings -> MessageDigest.isEqual(
                settings.verifier(), derive(passcode, settings.salt(), settings.iterations()))).orElse(false);
    }

    public void remove(String subject) { repository.delete(subject); }

    private static void validateWrappedKey(WrappedVaultKey key) {
        if (key == null) return; // Legacy clients are migrated when they next change or restore their passkey.
        if (key.currentVersion() < 1 || key.currentVersion() > 1_000_000 || key.createdAt() < 1 || key.wrappedAt() < 1
                || !"PBKDF2-SHA256/AES-256-GCM".equals(key.wrapping()) || key.iterations() != 600_000
                || !base64(key.salt(), 24) || !base64(key.iv(), 16) || !base64(key.wrappedMasterKey(), 64)) {
            throw new IllegalArgumentException("Invalid wrapped vault key metadata");
        }
    }

    private static boolean base64(String value, int length) {
        return value != null && value.length() == length && value.matches("[A-Za-z0-9+/]+={0,2}");
    }

    private static byte[] derive(String passcode, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(passcode.toCharArray(), salt, iterations, KEY_BITS);
        try { return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded(); }
        catch (GeneralSecurityException exception) { throw new IllegalStateException("Passkey hashing is unavailable", exception); }
        finally { spec.clearPassword(); }
    }

    public record LockConfig(boolean enabled, int timeoutSeconds, WrappedVaultKey wrappedKey) {
        public LockConfig(boolean enabled, int timeoutSeconds) { this(enabled, timeoutSeconds, null); }
    }
}
