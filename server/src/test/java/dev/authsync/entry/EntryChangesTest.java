package dev.authsync.entry;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class EntryChangesTest {
    private static final Instant NOW = Instant.parse("2026-10-21T12:00:00Z");
    private final AuthenticatorEntryRepository repository = mock(AuthenticatorEntryRepository.class);
    private final EntryService service = new EntryService(repository, Clock.fixed(NOW, ZoneOffset.UTC));

    @Test
    void deletionWinsWhenTheQueriesOverlap() {
        UUID deleted = UUID.randomUUID(), kept = UUID.randomUUID();
        var removedEntry = new AuthenticatorEntry(deleted, "user", "Encrypted", "Encrypted", new byte[32], new byte[12],
                1, "SHA1", 6, 30, NOW, NOW, UUID.randomUUID());
        var keptEntry = new AuthenticatorEntry(kept, "user", "Encrypted", "Encrypted", new byte[32], new byte[12],
                1, "SHA1", 6, 30, NOW, NOW, UUID.randomUUID());
        Instant since = NOW.minusSeconds(300);
        when(repository.findChangedSince("user", since)).thenReturn(
                new AuthenticatorEntryRepository.ChangeSet(List.of(removedEntry, keptEntry), List.of(deleted)));
        var changes = service.changes("user", since.toEpochMilli());
        assertThat(changes.entries()).extracting(EntryService.EntryResponse::id).containsExactly(kept);
        assertThat(changes.deletedIds()).containsExactly(deleted);
    }

    @Test
    void withoutACursorReturnsTheFullListAndACursorSlightlyInThePast() {
        when(repository.findAllByGoogleSubject("user")).thenReturn(List.of());

        EntryService.Changes changes = service.changes("user", null);

        assertThat(changes.full()).isTrue();
        assertThat(changes.deletedIds()).isEmpty();
        assertThat(changes.cursor()).isEqualTo(NOW.minusSeconds(60).toEpochMilli());
        verify(repository, never()).findChangedSince(any(), any());
    }

    @Test
    void withACursorReturnsOnlyChangesAndDeletions() {
        UUID deleted = UUID.randomUUID();
        Instant since = NOW.minusSeconds(300);
        when(repository.findChangedSince("user", since))
                .thenReturn(new AuthenticatorEntryRepository.ChangeSet(List.of(), List.of(deleted)));

        EntryService.Changes changes = service.changes("user", since.toEpochMilli());

        assertThat(changes.full()).isFalse();
        assertThat(changes.deletedIds()).containsExactly(deleted);
        verify(repository, never()).findAllByGoogleSubject(any());
    }

    @Test
    void aCursorOlderThanTheDeletionRecordsGetsTheFullList() {
        when(repository.findAllByGoogleSubject("user")).thenReturn(List.of());

        EntryService.Changes changes = service.changes("user", NOW.minus(EntryService.MAX_DELTA_AGE).minusSeconds(1).toEpochMilli());

        assertThat(changes.full()).isTrue();
        verify(repository, never()).findChangedSince(any(), any());
    }

    @Test
    void refusesCreationTimesFirestoreCannotStore() {
        String secret = java.util.Base64.getEncoder().encodeToString(new byte[32]);
        String iv = java.util.Base64.getEncoder().encodeToString(new byte[12]);
        AuthenticatedUser user = new AuthenticatedUser("user", null, null);
        EntryService.PutEntryRequest tooLate = new EntryService.PutEntryRequest("Encrypted", "Encrypted", secret, iv, 1, "SHA1", 6, 30,
                EntryService.MAX_TIMESTAMP_MILLIS + 1, UUID.randomUUID());
        EntryService.PutEntryRequest valid = new EntryService.PutEntryRequest("Encrypted", "Encrypted", secret, iv, 1, "SHA1", 6, 30,
                NOW.toEpochMilli(), UUID.randomUUID());

        assertThatThrownBy(() -> service.prepare(user, UUID.randomUUID(), tooLate)).isInstanceOf(IllegalArgumentException.class);
        assertThat(service.prepare(user, UUID.randomUUID(), valid).getCreatedAt()).isEqualTo(NOW);
    }

    @Test
    void futureAndOverflowSizedCursorsRepairWithFullSnapshot() {
        when(repository.findAllByGoogleSubject("user")).thenReturn(List.of());
        for(long since:List.of(NOW.plusSeconds(300).toEpochMilli(),Long.MAX_VALUE)) {
            var changes=service.changes("user",since);
            assertThat(changes.full()).isTrue();
            assertThat(changes.cursor()).isEqualTo(NOW.minusSeconds(60).toEpochMilli());
        }
        verify(repository,never()).findChangedSince(any(),any());
    }

    @Test
    void rejectsNegativeCursors() {
        assertThatThrownBy(() -> service.changes("user", -1L)).isInstanceOf(IllegalArgumentException.class);
        verifyNoInteractions(repository);
    }
}
