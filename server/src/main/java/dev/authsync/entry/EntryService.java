package dev.authsync.entry;

import org.springframework.stereotype.Service;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Set;
import java.util.UUID;

@Service
public class EntryService {
    /** Upper bound on accounts per user, so one account (or a stolen session) cannot fill the database. */
    public static final int MAX_ENTRIES_PER_USER = 1000;
    private static final Set<String> ALGORITHMS = Set.of("SHA1", "SHA256", "SHA512");
    // Cursors point a little into the past so a write that committed while a sync was reading is never
    // missed; re-sending a few recent changes is harmless because clients apply them idempotently.
    private static final Duration CURSOR_OVERLAP = Duration.ofSeconds(60);
    // Old cursors use a full list to bound delta responses. Deletion markers themselves reserve UUIDs permanently.
    static final Duration MAX_DELTA_AGE = Duration.ofHours(36);
    static final long MAX_TIMESTAMP_MILLIS = 253_402_300_799_999L; // 9999-12-31T23:59:59.999Z
    private final AuthenticatorEntryRepository repository;
    private final Clock clock;

    public EntryService(AuthenticatorEntryRepository repository, Clock clock) {
        this.repository = repository;
        this.clock = clock;
    }

    public List<EntryResponse> list(String subject) {
        return repository.findAllByGoogleSubject(subject).stream().map(EntryService::response).toList();
    }

    /**
     * Without {@code sinceEpochMillis}: every entry (a full list). With it: only entries changed and IDs
     * deleted after that point. Either way the response carries the cursor for the next call.
     */
    public Changes changes(String subject, Long sinceEpochMillis) {
        if (sinceEpochMillis != null && sinceEpochMillis < 0) throw new IllegalArgumentException("since must not be negative");
        Instant syncTime = repository.synchronizationTime(subject, clock.instant());
        if (syncTime == null) syncTime = clock.instant();
        long cursor = syncTime.minus(CURSOR_OVERLAP).toEpochMilli();
        if (sinceEpochMillis == null) return new Changes(list(subject), List.of(), cursor, true);
        // Old clients or a damaged local cursor can point ahead of the database clock. Repair with a full snapshot.
        if (sinceEpochMillis > syncTime.toEpochMilli()) return new Changes(list(subject), List.of(), cursor, true);
        if (Instant.ofEpochMilli(sinceEpochMillis).isBefore(syncTime.minus(MAX_DELTA_AGE))) {
            return new Changes(list(subject), List.of(), cursor, true);
        }
        AuthenticatorEntryRepository.ChangeSet changes = repository.findChangedSince(subject, Instant.ofEpochMilli(sinceEpochMillis));
        // Entry and tombstone queries can straddle a deletion. UUIDs are never reused, so the tombstone wins.
        Set<UUID> deleted = Set.copyOf(changes.deletedIds());
        return new Changes(changes.changed().stream().filter(entry -> !deleted.contains(entry.getId()))
                .map(EntryService::response).toList(), changes.deletedIds(), cursor, changes.full());
    }

    public EntryResponse put(AuthenticatedUser user, UUID id, PutEntryRequest request) {
        AuthenticatorEntry entry = prepare(user, id, request);
        return response(request.baseMutationId() == null ? repository.save(entry, user) : repository.save(entry, user, request.baseMutationId()));
    }

    /** Validates a client write and builds the entry to store (no database access). */
    public AuthenticatorEntry prepare(AuthenticatedUser user, UUID id, PutEntryRequest request) {
        requireUuidV4(id, "Entry ID");
        requireUuidV4(request.mutationId(), "Mutation ID");
        byte[] ciphertext = decode(request.encryptedSecret(), "Encrypted secret");
        byte[] iv = decode(request.secretIv(), "Secret IV");
        if (iv.length != 12) throw new IllegalArgumentException("Secret IV must contain exactly 12 bytes");
        // Base32 secrets are at most a few hundred characters; 1 KiB of ciphertext leaves ample room.
        if (ciphertext.length < 17 || ciphertext.length > 1024) throw new IllegalArgumentException("Encrypted secret has an invalid size");
        if (request.keyVersion() < 1) throw new IllegalArgumentException("Key version must be positive");
        String algorithm = request.algorithm().toUpperCase();
        if (!ALGORITHMS.contains(algorithm)) throw new IllegalArgumentException("Unsupported TOTP algorithm");
        if (request.digits() < 6 || request.digits() > 8) throw new IllegalArgumentException("TOTP digits must be between 6 and 8");
        if (request.periodSeconds() < 15 || request.periodSeconds() > 120) throw new IllegalArgumentException("TOTP period must be between 15 and 120 seconds");
        byte[] encryptedLabel = null, labelIv = null;
        boolean hasLabel = request.encryptedLabel() != null && !request.encryptedLabel().isBlank();
        boolean hasLabelIv = request.labelIv() != null && !request.labelIv().isBlank();
        if (hasLabel != hasLabelIv) throw new IllegalArgumentException("Encrypted label and label IV must be sent together");
        if (hasLabel) {
            encryptedLabel = decode(request.encryptedLabel(), "Encrypted label");
            labelIv = decode(request.labelIv(), "Label IV");
            if (labelIv.length != 12) throw new IllegalArgumentException("Label IV must contain exactly 12 bytes");
            if (encryptedLabel.length < 17 || encryptedLabel.length > 2048) throw new IllegalArgumentException("Encrypted label has an invalid size");
        }

        Instant now = clock.instant();
        // Firestore timestamps end at 9999-12-31; a later value would fail when stored.
        if (request.createdAtEpochMillis() < 1 || request.createdAtEpochMillis() > MAX_TIMESTAMP_MILLIS) {
            throw new IllegalArgumentException("Created time is out of range");
        }
        Instant createdAt = Instant.ofEpochMilli(request.createdAtEpochMillis());
        return new AuthenticatorEntry(id, user.googleSubject(), request.issuer().trim(),
                request.accountName().trim(), ciphertext, iv, request.keyVersion(), algorithm,
                request.digits(), request.periodSeconds(), createdAt, now, request.mutationId(), encryptedLabel, labelIv);
    }

    public void delete(String subject, UUID id) {
        requireUuidV4(id, "Entry ID");
        repository.deleteByIdAndGoogleSubject(id, subject);
    }

    public void delete(AuthenticatedUser user, UUID id) {
        requireUuidV4(id, "Entry ID");
        repository.deleteByIdAndUser(id, user);
    }

    /**
     * Applies queued client changes in order with a single database transaction. Processing stops at the
     * first rejected change; the result says how many were applied so the client keeps the rest queued.
     */
    public BatchOutcome applyBatch(AuthenticatedUser user, List<BatchChange> changes) {
        List<AuthenticatorEntryRepository.Mutation> mutations = new ArrayList<>();
        String rejection = null;
        for (BatchChange change : changes) {
            try {
                if (change.delete()) {
                    requireUuidV4(change.id(), "Entry ID");
                    mutations.add(new AuthenticatorEntryRepository.Mutation(change.id(), null));
                } else {
                    mutations.add(new AuthenticatorEntryRepository.Mutation(change.id(), prepare(user, change.id(), change.request()),
                            change.request().baseMutationId()));
                }
            } catch (IllegalArgumentException exception) {
                rejection = exception.getMessage();
                break;
            }
        }
        AuthenticatorEntryRepository.BatchResult result = mutations.isEmpty()
                ? new AuthenticatorEntryRepository.BatchResult(0, null, List.of())
                : repository.applyBatch(user, mutations);
        if (result.error() != null) return new BatchOutcome(result.applied(), result.error(), result.errorCode());
        return new BatchOutcome(result.applied(), rejection);
    }

    public static EntryResponse response(AuthenticatorEntry entry) {
        Base64.Encoder base64 = Base64.getEncoder();
        byte[] label = entry.getEncryptedLabel(), labelIv = entry.getLabelIv();
        return new EntryResponse(entry.getId(), entry.getIssuer(), entry.getAccountName(),
                base64.encodeToString(entry.getEncryptedSecret()),
                base64.encodeToString(entry.getSecretIv()), entry.getKeyVersion(),
                entry.getAlgorithm(), entry.getDigits(), entry.getPeriodSeconds(),
                entry.getCreatedAt().toEpochMilli(), entry.getUpdatedAt().toEpochMilli(), entry.getMutationId(),
                label == null ? null : base64.encodeToString(label), labelIv == null ? null : base64.encodeToString(labelIv));
    }

    private static byte[] decode(String value, String field) {
        try { return Base64.getDecoder().decode(value); }
        catch (IllegalArgumentException | NullPointerException exception) { throw new IllegalArgumentException(field + " must be valid Base64"); }
    }

    public static void requireUuidV4(UUID id, String field) {
        if (id == null || id.version() != 4 || id.variant() != 2) throw new IllegalArgumentException(field + " must be a UUIDv4");
    }

    public record EntryResponse(UUID id, String issuer, String accountName, String encryptedSecret,
                                String secretIv, int keyVersion, String algorithm, int digits,
                                int periodSeconds, long createdAtEpochMillis, long updatedAtEpochMillis,
                                UUID mutationId, String encryptedLabel, String labelIv) {}

    public record Changes(List<EntryResponse> entries, List<UUID> deletedIds, long cursor, boolean full) {}

    public record BatchChange(UUID id, boolean delete, PutEntryRequest request) {}

    /** {@code errorCode}: why the change after the applied ones was refused (e.g. STALE_KEY), or null. */
    public record BatchOutcome(int applied, String error, String errorCode) {
        public BatchOutcome(int applied, String error) { this(applied, error, null); }
    }

    /** {@code baseMutationId}: the stored mutation an edit was made from (null for a new entry or an older client). */
    public record PutEntryRequest(String issuer, String accountName, String encryptedSecret, String secretIv,
                                  int keyVersion, String algorithm, int digits, int periodSeconds,
                                  long createdAtEpochMillis, UUID mutationId, String encryptedLabel, String labelIv,
                                  UUID baseMutationId) {
        public PutEntryRequest(String issuer, String accountName, String encryptedSecret, String secretIv,
                               int keyVersion, String algorithm, int digits, int periodSeconds,
                               long createdAtEpochMillis, UUID mutationId) {
            this(issuer, accountName, encryptedSecret, secretIv, keyVersion, algorithm, digits, periodSeconds,
                    createdAtEpochMillis, mutationId, null, null, null);
        }
        public PutEntryRequest(String issuer, String accountName, String encryptedSecret, String secretIv,
                               int keyVersion, String algorithm, int digits, int periodSeconds,
                               long createdAtEpochMillis, UUID mutationId, String encryptedLabel, String labelIv) {
            this(issuer, accountName, encryptedSecret, secretIv, keyVersion, algorithm, digits, periodSeconds,
                    createdAtEpochMillis, mutationId, encryptedLabel, labelIv, null);
        }
    }
}
