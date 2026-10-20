package dev.authsync.lock;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class LockServiceTest {
    private final InMemoryRepository repository = new InMemoryRepository();
    private final LockService service = new LockService(repository);

    @Test
    void configuresAndVerifiesAPasskeyWithoutStoringPlaintext() {
        LockService.LockConfig config = service.configure("google-user", "4826", 300, true, null);

        assertThat(config).isEqualTo(new LockService.LockConfig(true, 300, true, null));
        assertThat(service.verify("google-user", "4826")).isTrue();
        assertThat(service.verify("google-user", "wrong")).isFalse();

        LockSettings stored = repository.find("google-user").orElseThrow();
        assertThat(stored.verifier()).isNotEqualTo("4826".getBytes());
        assertThat(stored.salt()).hasSize(16);
        assertThat(stored.iterations()).isEqualTo(210_000);
    }

    @Test
    void isolatesSettingsByGoogleUser() {
        service.configure("user-a", "alpha-key", 300);

        assertThat(service.verify("user-a", "alpha-key")).isTrue();
        assertThat(service.verify("user-b", "alpha-key")).isFalse();
        assertThat(service.config("user-b")).isEqualTo(new LockService.LockConfig(false, 0));
    }

    @Test
    void rejectsShortPasskeysAndUnknownTimeouts() {
        assertThatThrownBy(() -> service.configure("user", "123", 300))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("4 to 128");
        assertThatThrownBy(() -> service.configure("user", "1234", 60))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("timeout");
        assertThatThrownBy(() -> service.configure("user", "1234", 0))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("timeout");
        assertThat(service.configure("user", "1234", 1800).timeoutSeconds()).isEqualTo(1800);
        assertThat(service.configure("user", "1234", 604800).timeoutSeconds()).isEqualTo(604800);
        assertThatThrownBy(() -> service.configure("user", "1234", 604801))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("timeout");
    }

    @Test
    void acceptsEverySupportedLockDuration() {
        List.of(300, 600, 900, 1200, 1500, 1800, 2100, 2400, 2700, 3000, 3300,
                        3600, 7200, 14400, 28800, 43200, 86400, 172800, 604800)
                .forEach(timeout -> assertThat(service.configure("user-" + timeout, "1234", timeout).timeoutSeconds())
                        .isEqualTo(timeout));
    }

    @Test
    void keepsSupportedOneHourSettings() {
        repository.save("legacy-user", new LockSettings(new byte[16], new byte[32], 210_000, 3600));

        assertThat(service.config("legacy-user")).isEqualTo(new LockService.LockConfig(true, 3600));
    }

    @Test
    void migratesUnsupportedLegacySettingsToFiveMinutes() {
        repository.save("legacy-user", new LockSettings(new byte[16], new byte[32], 210_000, 0));

        assertThat(service.config("legacy-user")).isEqualTo(new LockService.LockConfig(true, 300));
    }

    @Test
    void removesExistingLockSettings() {
        service.configure("user", "1234", 300);

        service.remove("user");

        assertThat(service.config("user")).isEqualTo(new LockService.LockConfig(false, 0));
        assertThat(service.verify("user", "1234")).isFalse();
    }

    private static final class InMemoryRepository implements LockSettingsRepository {
        private final Map<String, LockSettings> settings = new HashMap<>();

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
    }
}
