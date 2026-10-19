package dev.authsync.entry;

import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
public class EntryService {
    private static final Set<String> ALGORITHMS = Set.of("SHA1", "SHA256", "SHA512");
    private final AuthenticatorEntryRepository repository;
    private final Clock clock;

    public EntryService(AuthenticatorEntryRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    public List<EntryResponse> list(String subject) {
        return repository.findAllByGoogleSubject(subject).stream().map(EntryService::response).toList();
    }

    public EntryResponse put(AuthenticatedUser user, UUID id, PutEntryRequest request) {
        requireUuidV4(id, "Entry ID");
        requireUuidV4(request.mutationId(), "Mutation ID");
        byte[] ciphertext = decode(request.encryptedSecret(), "Encrypted secret");
        byte[] iv = decode(request.secretIv(), "Secret IV");
        if (iv.length != 12) throw new IllegalArgumentException("Secret IV must contain exactly 12 bytes");
        if (ciphertext.length < 17 || ciphertext.length > 4096) throw new IllegalArgumentException("Encrypted secret has an invalid size");
        if (request.keyVersion() < 1) throw new IllegalArgumentException("Key version must be positive");
        String algorithm = request.algorithm().toUpperCase();
        if (!ALGORITHMS.contains(algorithm)) throw new IllegalArgumentException("Unsupported TOTP algorithm");
        if (request.digits() < 6 || request.digits() > 8) throw new IllegalArgumentException("TOTP digits must be between 6 and 8");
        if (request.periodSeconds() < 15 || request.periodSeconds() > 120) throw new IllegalArgumentException("TOTP period must be between 15 and 120 seconds");

        Instant now = clock.instant();
        Instant createdAt = Instant.ofEpochMilli(request.createdAtEpochMillis());
        AuthenticatorEntry entry = new AuthenticatorEntry(id, user.googleSubject(), request.issuer().trim(),
                request.accountName().trim(), ciphertext, iv, request.keyVersion(), algorithm,
                request.digits(), request.periodSeconds(), createdAt, now, request.mutationId());
        return response(repository.save(entry, user));
    }

    public void delete(String subject, UUID id) {
        requireUuidV4(id, "Entry ID");
        repository.deleteByIdAndGoogleSubject(id, subject);
    }

    private static EntryResponse response(AuthenticatorEntry entry) {
        return new EntryResponse(entry.getId(), entry.getIssuer(), entry.getAccountName(),
                Base64.getEncoder().encodeToString(entry.getEncryptedSecret()),
                Base64.getEncoder().encodeToString(entry.getSecretIv()), entry.getKeyVersion(),
                entry.getAlgorithm(), entry.getDigits(), entry.getPeriodSeconds(),
                entry.getCreatedAt().toEpochMilli(), entry.getUpdatedAt().toEpochMilli(), entry.getMutationId());
    }

    private static byte[] decode(String value, String field) {
        try { return Base64.getDecoder().decode(value); }
        catch (IllegalArgumentException exception) { throw new IllegalArgumentException(field + " must be valid Base64"); }
    }

    private static void requireUuidV4(UUID id, String field) {
        if (id.version() != 4 || id.variant() != 2) throw new IllegalArgumentException(field + " must be a UUIDv4");
    }

    public record EntryResponse(UUID id, String issuer, String accountName, String encryptedSecret,
                                String secretIv, int keyVersion, String algorithm, int digits,
                                int periodSeconds, long createdAtEpochMillis, long updatedAtEpochMillis,
                                UUID mutationId) {}

    public record PutEntryRequest(String issuer, String accountName, String encryptedSecret, String secretIv,
                                  int keyVersion, String algorithm, int digits, int periodSeconds,
                                  long createdAtEpochMillis, UUID mutationId) {}
}
