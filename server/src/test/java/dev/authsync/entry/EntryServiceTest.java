package dev.authsync.entry;

import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class EntryServiceTest {
    private final AuthenticatorEntryRepository repository = mock(AuthenticatorEntryRepository.class);
    private final EntryService service = new EntryService(repository,
            Clock.fixed(Instant.parse("2026-10-19T06:30:00Z"), ZoneOffset.UTC));

    @Test
    void storesOnlyClientCiphertextAndScopesOwnerFromAuthenticatedUser() {
        when(repository.save(any(), any())).thenAnswer(invocation -> invocation.getArgument(0));
        UUID id = UUID.fromString("e57b75d1-7a52-4d15-92d4-6b4c32af752c");
        UUID mutation = UUID.fromString("77d8d471-107d-44e7-a352-254ba4797313");
        byte[] ciphertext = new byte[33];
        byte[] iv = new byte[12];
        var request = new EntryService.PutEntryRequest("Example", "person@example.com",
                Base64.getEncoder().encodeToString(ciphertext), Base64.getEncoder().encodeToString(iv),
                1, "SHA1", 6, 30, 1_760_854_000_000L, mutation);

        EntryService.EntryResponse response = service.put(new AuthenticatedUser("google-sub", "person@example.com", "Person"), id, request);

        assertThat(response.encryptedSecret()).isEqualTo(request.encryptedSecret());
        verify(repository).save(argThat(entry -> entry.getGoogleSubject().equals("google-sub")
                && entry.getKeyVersion() == 1 && entry.getMutationId().equals(mutation)), any());
    }

    @Test
    void anEditPassesTheVersionItWasMadeFromToTheRepository() {
        UUID base = UUID.randomUUID();
        when(repository.save(any(), any(), any())).thenAnswer(invocation -> invocation.getArgument(0));
        var request = new EntryService.PutEntryRequest("Encrypted", "Encrypted",
                Base64.getEncoder().encodeToString(new byte[33]), Base64.getEncoder().encodeToString(new byte[12]),
                1, "SHA1", 6, 30, 1_760_854_000_000L, UUID.randomUUID(), null, null, base);

        service.put(new AuthenticatedUser("google-sub", null, null), UUID.randomUUID(), request);

        verify(repository).save(any(), any(), eq(base));
        verify(repository, never()).save(any(), any());
    }

    @Test
    void rejectsGuessableNonV4EntryIdentifiers() {
        UUID sequential = UUID.fromString("00000000-0000-1000-8000-000000000001");
        var request = new EntryService.PutEntryRequest("Example", "person@example.com",
                Base64.getEncoder().encodeToString(new byte[33]), Base64.getEncoder().encodeToString(new byte[12]),
                1, "SHA1", 6, 30, 1L, UUID.randomUUID());

        assertThatThrownBy(() -> service.put(new AuthenticatedUser("subject", null, null), sequential, request))
                .isInstanceOf(IllegalArgumentException.class).hasMessageContaining("UUIDv4");
        verifyNoInteractions(repository);
    }

    @Test
    void deletionUsesAuthenticatedSubjectAndIsIdempotentAtRepositoryBoundary() {
        UUID id = UUID.randomUUID();
        service.delete("verified-subject", id);
        verify(repository).deleteByIdAndGoogleSubject(id, "verified-subject");
    }
}
