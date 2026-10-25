package dev.authsync.lock;

import com.google.cloud.firestore.DocumentSnapshot;
import dev.authsync.vault.VaultChangedException;
import org.junit.jupiter.api.Test;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class VaultRevisionRulesTest {
    @Test
    void aStaleExpectedRevisionIsRefused() {
        DocumentSnapshot stored = document(Map.of("vaultRevision", 4L, "wrappedVaultKey", "k", "wrappedVaultKeyVersion", 2L));

        assertThatThrownBy(() -> FirestoreLockSettingsRepository.requireSafeKeyChange(stored, key(2), 3L))
                .isInstanceOf(VaultChangedException.class);
        assertThatCode(() -> FirestoreLockSettingsRepository.requireSafeKeyChange(stored, key(2), 4L)).doesNotThrowAnyException();
    }

    @Test
    void anOlderKeyVersionIsRefusedEvenFromClientsThatSendNoRevision() {
        DocumentSnapshot stored = document(Map.of("vaultRevision", 4L, "wrappedVaultKey", "k", "wrappedVaultKeyVersion", 3L));

        assertThatThrownBy(() -> FirestoreLockSettingsRepository.requireSafeKeyChange(stored, key(2), null))
                .isInstanceOf(VaultChangedException.class);
        assertThatCode(() -> FirestoreLockSettingsRepository.requireSafeKeyChange(stored, key(3), null)).doesNotThrowAnyException();
    }

    @Test
    void onceRequiredAKeyChangeWithoutARevisionIsRefused() {
        DocumentSnapshot stored = document(Map.of("vaultRevision", 4L, "wrappedVaultKey", "k", "wrappedVaultKeyVersion", 1L));

        assertThatThrownBy(() -> FirestoreLockSettingsRepository.requireSafeKeyChange(stored, key(1), null, true))
                .isInstanceOf(VaultChangedException.class);
        assertThatCode(() -> FirestoreLockSettingsRepository.requireSafeKeyChange(stored, key(1), 4L, true)).doesNotThrowAnyException();
        assertThatCode(() -> FirestoreLockSettingsRepository.requireSafeKeyChange(stored, key(1), null, false)).doesNotThrowAnyException();
    }

    @Test
    void aResetIsInProgressOnlyUntilItGoesStale() {
        java.time.Instant now = java.time.Instant.parse("2026-10-22T12:00:00Z");
        DocumentSnapshot running = document(Map.of("vaultResetStatus", "IN_PROGRESS"));
        when(running.getTimestamp("vaultResetAt")).thenReturn(com.google.cloud.Timestamp.ofTimeSecondsAndNanos(now.minusSeconds(30).getEpochSecond(), 0));
        DocumentSnapshot interrupted = document(Map.of("vaultResetStatus", "IN_PROGRESS"));
        when(interrupted.getTimestamp("vaultResetAt")).thenReturn(com.google.cloud.Timestamp.ofTimeSecondsAndNanos(now.minusSeconds(600).getEpochSecond(), 0));

        assertThat(FirestoreLockSettingsRepository.resetInProgress(running, now)).isTrue();
        assertThat(FirestoreLockSettingsRepository.resetInterrupted(running, now)).isFalse();
        assertThat(FirestoreLockSettingsRepository.resetInProgress(interrupted, now)).isFalse();
        assertThat(FirestoreLockSettingsRepository.resetInterrupted(interrupted, now)).isTrue();
    }

    @Test
    void aResetVaultIsNotAnExistingAccount() {
        DocumentSnapshot reset = document(Map.of("vaultRevision", 5L, "vaultResetAt", "now"));
        DocumentSnapshot account = document(Map.of("googleSubject", "user", "entryCount", 2L));

        assertThat(FirestoreLockSettingsRepository.accountExists(reset)).isFalse();
        assertThat(FirestoreLockSettingsRepository.resetWithoutKey(reset)).isTrue();
        assertThat(FirestoreLockSettingsRepository.accountExists(account)).isTrue();
        assertThat(FirestoreLockSettingsRepository.revision(reset)).isEqualTo(5L);
        assertThat(FirestoreLockSettingsRepository.revision(account)).isZero();
    }

    private static DocumentSnapshot document(Map<String, Object> fields) {
        Map<String, Object> data = new HashMap<>(fields);
        DocumentSnapshot document = mock(DocumentSnapshot.class);
        when(document.exists()).thenReturn(true);
        when(document.getData()).thenReturn(data);
        when(document.get(org.mockito.ArgumentMatchers.anyString())).thenAnswer(call -> data.get(call.<String>getArgument(0)));
        when(document.getString(org.mockito.ArgumentMatchers.anyString())).thenAnswer(call -> {
            Object value = data.get(call.<String>getArgument(0));
            return value instanceof String text ? text : null;
        });
        when(document.getLong(org.mockito.ArgumentMatchers.anyString())).thenAnswer(call -> {
            Object value = data.get(call.<String>getArgument(0));
            return value instanceof Long number ? number : null;
        });
        return document;
    }

    private static WrappedVaultKey key(int version) {
        String salt = Base64.getEncoder().encodeToString(new byte[16]);
        String iv = Base64.getEncoder().encodeToString(new byte[12]);
        return new WrappedVaultKey(version, 1, 1, "PBKDF2-SHA256/AES-256-GCM", 600_000, salt, iv,
                Base64.getEncoder().encodeToString(new byte[48]));
    }
}
