package dev.authsync.lock;

import org.junit.jupiter.api.Test;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LockServiceTest {
    private final InMemoryRepository repository = new InMemoryRepository();
    private final LockService service = new LockService(repository);

    @Test
    void storesLockPreferencesAndTheWrappedKeyButNoPasskeyMaterial() {
        WrappedVaultKey key = wrappedKey();
        LockService.LockConfig config = service.configure("google-user", 300, true, key);

        assertThat(config).isEqualTo(new LockService.LockConfig(true, 300, true, key));
        LockSettings stored = repository.find("google-user").orElseThrow();
        assertThat(stored.hasLegacyVerifier()).isFalse();
        assertThat(stored.wrappedKey()).isEqualTo(key);
    }

    @Test
    void isolatesSettingsByGoogleUser() {
        service.configure("user-a", 300, false, wrappedKey());

        assertThat(service.config("user-a").enabled()).isTrue();
        assertThat(service.config("user-b")).isEqualTo(new LockService.LockConfig(false, 0));
    }

    @Test
    void rejectsUnknownTimeoutsAndMalformedWrappedKeys() {
        assertThatThrownBy(() -> service.configure("user", 60, false, null))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("timeout");
        assertThatThrownBy(() -> service.configure("user", 0, false, null))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("timeout");
        assertThatThrownBy(() -> service.configure("user", 604801, false, null))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("timeout");
        WrappedVaultKey weak = new WrappedVaultKey(1, 1, 1, "PBKDF2-SHA256/AES-256-GCM", 1000,
                base64(16), base64(12), base64(48));
        assertThatThrownBy(() -> service.configure("user", 300, false, weak))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("wrapped vault key");
        assertThat(service.configure("user", 1800, false, null).timeoutSeconds()).isEqualTo(1800);
        assertThat(service.configure("user", 604800, false, null).timeoutSeconds()).isEqualTo(604800);
    }

    @Test
    void acceptsEverySupportedLockDuration() {
        List.of(300, 600, 900, 1200, 1500, 1800, 2100, 2400, 2700, 3000, 3300,
                        3600, 7200, 14400, 28800, 43200, 86400, 172800, 604800)
                .forEach(timeout -> assertThat(service.configure("user-" + timeout, timeout, false, wrappedKey()).timeoutSeconds())
                        .isEqualTo(timeout));
    }

    @Test
    void keepsSupportedOneHourSettings() {
        repository.save("legacy-user", new LockSettings(3600, false, null));

        assertThat(service.config("legacy-user")).isEqualTo(new LockService.LockConfig(true, 3600));
    }

    @Test
    void migratesUnsupportedLegacySettingsToFiveMinutes() {
        repository.save("legacy-user", new LockSettings(0, false, null));

        assertThat(service.config("legacy-user")).isEqualTo(new LockService.LockConfig(true, 300));
    }

    @Test
    void aLegacyServerSideVerifierIsDeletedOnTheNextRead() throws Exception {
        byte[] salt = new byte[16];
        byte[] verifier = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
                .generateSecret(new PBEKeySpec("4826".toCharArray(), salt, 1000, 256)).getEncoded();
        repository.save("old-user", new LockSettings(300, false, null, salt, verifier, 1000));

        assertThat(service.config("old-user").enabled()).isTrue();
        assertThat(repository.legacyVerifiersDeleted).contains("old-user");
        assertThat(repository.find("old-user").orElseThrow().hasLegacyVerifier()).isFalse();
    }

    @Test
    void acceptsArgon2idWrappedKeysWithinSafeParameters() {
        WrappedVaultKey argon2id = new WrappedVaultKey(1, 1, 1, LockService.ARGON2ID_WRAPPING, 3,
                base64(16), base64(12), base64(48), 65_536, 1);
        assertThat(service.configure("user", 300, false, argon2id).wrappedKey()).isEqualTo(argon2id);

        WrappedVaultKey tooLittleMemory = new WrappedVaultKey(1, 1, 1, LockService.ARGON2ID_WRAPPING, 3,
                base64(16), base64(12), base64(48), 1024, 1);
        assertThatThrownBy(() -> service.configure("user", 300, false, tooLittleMemory)).isInstanceOf(IllegalArgumentException.class);
        WrappedVaultKey pbkdf2WithMemory = new WrappedVaultKey(1, 1, 1, LockService.PBKDF2_WRAPPING, 600_000,
                base64(16), base64(12), base64(48), 65_536, 1);
        assertThatThrownBy(() -> service.configure("user", 300, false, pbkdf2WithMemory)).isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void accountStateReportsExistenceAndLockTogether() {
        assertThat(service.accountState("nobody")).isEqualTo(new LockService.AccountState(false, new LockService.LockConfig(false, 0)));
        service.configure("user", 900, false, null);
        assertThat(service.accountState("user").exists()).isTrue();
        assertThat(service.accountState("user").lock().timeoutSeconds()).isEqualTo(900);
    }

    @Test
    void removesExistingLockSettings() {
        service.configure("user", 300, false, wrappedKey());

        service.remove("user");

        assertThat(service.config("user")).isEqualTo(new LockService.LockConfig(false, 0));
    }

    private static WrappedVaultKey wrappedKey() {
        return new WrappedVaultKey(1, 1_760_000_000_000L, 1_760_000_000_000L, "PBKDF2-SHA256/AES-256-GCM", 600_000,
                base64(16), base64(12), base64(48));
    }

    private static String base64(int bytes) { return Base64.getEncoder().encodeToString(new byte[bytes]); }

    private static final class InMemoryRepository implements LockSettingsRepository {
        private final Map<String, LockSettings> settings = new HashMap<>();
        private final Set<String> legacyVerifiersDeleted = new HashSet<>();

        @Override
        public Optional<LockSettings> find(String googleSubject) {
            return Optional.ofNullable(settings.get(googleSubject));
        }

        @Override
        public void save(String googleSubject, LockSettings lockSettings) {
            settings.put(googleSubject, lockSettings);
        }

        @Override
        public void delete(String googleSubject) {
            settings.remove(googleSubject);
        }

        @Override
        public void deleteLegacyVerifier(String googleSubject) {
            LockSettings current = settings.get(googleSubject);
            if (current != null) settings.put(googleSubject, new LockSettings(current.timeoutSeconds(), current.lockOnScreenLock(), current.wrappedKey()));
            legacyVerifiersDeleted.add(googleSubject);
        }
    }
}
