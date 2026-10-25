package dev.authsync.vault;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.QueryDocumentSnapshot;
import com.google.cloud.firestore.SetOptions;
import dev.authsync.config.AuthSyncProperties;
import dev.authsync.entry.AuthenticatedUser;
import dev.authsync.entry.AuthenticatorEntry;
import dev.authsync.entry.EntryService;
import dev.authsync.entry.FirestoreAuthenticatorEntryRepository;
import dev.authsync.lock.FirestoreLockSettingsRepository;
import dev.authsync.lock.LockService;
import dev.authsync.lock.LockSettings;
import dev.authsync.lock.WrappedVaultKey;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutionException;

/**
 * Recovery-key rotation in one Firestore transaction: the new wrapped vault key and every re-encrypted
 * entry become visible together, so no device can ever see a new key next to old-key ciphertext.
 * The rotation is refused if any entry was added, removed or changed since the client prepared it, or if
 * the wrapped key changed (another device's passphrase change, rotation or vault reset) since then.
 */
@Service
public class VaultRotationService {
    /**
     * Every account a user may store. Firestore limits a transaction by its 10 MiB request size (documents
     * plus their index entries). Entry fields are capped (about 3.5 KB per account at most), only updatedAt is
     * indexed (firestore.indexes.json) and the rotation body is capped at 6 MiB, so 1,000 accounts fit.
     */
    public static final int MAX_ROTATION_ENTRIES = EntryService.MAX_ENTRIES_PER_USER;
    private final Firestore firestore;
    private final EntryService entryService;
    private final boolean requireRevision;

    @Autowired
    public VaultRotationService(Firestore firestore, EntryService entryService, AuthSyncProperties properties) {
        this.firestore = firestore;
        this.entryService = entryService;
        this.requireRevision = properties.requireVaultRevision();
    }

    public VaultRotationService(Firestore firestore, EntryService entryService) {
        this.firestore = firestore;
        this.entryService = entryService;
        this.requireRevision = false;
    }

    public Result rotate(AuthenticatedUser user, Map<UUID, UUID> previousMutations, Map<UUID, EntryService.PutEntryRequest> entries,
                         WrappedVaultKey wrappedKey, int timeoutSeconds, boolean lockOnScreenLock) {
        return rotate(user, previousMutations, entries, wrappedKey, timeoutSeconds, lockOnScreenLock, null);
    }

    /** {@code expectedRevision}: the vault revision the client prepared against (null from older clients). */
    public Result rotate(AuthenticatedUser user, Map<UUID, UUID> previousMutations, Map<UUID, EntryService.PutEntryRequest> entries,
                         WrappedVaultKey wrappedKey, int timeoutSeconds, boolean lockOnScreenLock, Long expectedRevision) {
        return rotate(user, previousMutations, entries, wrappedKey, timeoutSeconds, lockOnScreenLock, expectedRevision, ignored -> {});
    }

    public Result rotate(AuthenticatedUser user, Map<UUID, UUID> previousMutations, Map<UUID, EntryService.PutEntryRequest> entries,
                         WrappedVaultKey wrappedKey, int timeoutSeconds, boolean lockOnScreenLock, Long expectedRevision,
                         java.util.function.IntConsumer chargeRead) {
        if (wrappedKey == null) throw new IllegalArgumentException("wrappedKey: must not be null");
        LockService.validateWrappedKey(wrappedKey);
        LockService.requireAllowedTimeout(timeoutSeconds);
        if (entries.size() > MAX_ROTATION_ENTRIES) {
            throw new IllegalArgumentException("Key rotation supports at most " + MAX_ROTATION_ENTRIES + " accounts");
        }
        if (!previousMutations.keySet().equals(entries.keySet())) {
            throw new IllegalArgumentException("Every rotated entry needs its previous mutation ID");
        }
        List<AuthenticatorEntry> prepared = entries.entrySet().stream()
                .map(item -> entryService.prepare(user, item.getKey(), item.getValue())).toList();
        for (AuthenticatorEntry entry : prepared) {
            if (entry.getKeyVersion() != wrappedKey.currentVersion()) {
                throw new IllegalArgumentException("Rotated entries must use the new key version");
            }
        }
        LockSettings lock = new LockSettings(timeoutSeconds, lockOnScreenLock, wrappedKey);
        String subject = user.googleSubject();
        DocumentReference userDocument = firestore.collection("users").document(subject);
        long revision = await(firestore.runTransaction(transaction -> {
            // The user document is read in the transaction too, so a concurrent passphrase change, rotation or
            // vault reset makes this transaction retry and then fail the checks below instead of being overwritten.
            DocumentSnapshot profile = transaction.get(userDocument).get();
            if (FirestoreLockSettingsRepository.resetRunning(profile) || FirestoreLockSettingsRepository.resetWithoutKey(profile)
                    || user.vaultGeneration() != FirestoreLockSettingsRepository.generation(profile)) {
                throw new VaultChangedException("This vault was reset on another device. Sign in again.");
            }
            FirestoreLockSettingsRepository.requireSafeKeyChange(profile, wrappedKey, expectedRevision, requireRevision);
            Long storedVersion = FirestoreLockSettingsRepository.wrappedKeyVersion(profile);
            if (storedVersion != null && wrappedKey.currentVersion() <= storedVersion) {
                throw new VaultChangedException("The recovery key was already rotated on another device. Lock and unlock Lockstep, then try again.");
            }
            Long count = profile.exists() ? profile.getLong(FirestoreLockSettingsRepository.ENTRY_COUNT) : null;
            chargeRead.accept(count == null ? EntryService.MAX_ENTRIES_PER_USER : (int) Math.min(EntryService.MAX_ENTRIES_PER_USER, Math.max(0L, count)));
            List<QueryDocumentSnapshot> documents = transaction.get(userDocument.collection("authenticatorEntries")).get().getDocuments();
            Map<UUID, UUID> current = new HashMap<>();
            for (DocumentSnapshot document : documents) {
                if (!FirestoreAuthenticatorEntryRepository.isCurrentSchema(document)) continue;
                current.put(UUID.fromString(document.getId()), UUID.fromString(String.valueOf(document.getString("mutationId"))));
            }
            if (!current.equals(previousMutations)) {
                throw new VaultChangedException("Your accounts changed on another device during the rotation. Nothing was changed; try again.");
            }
            for (AuthenticatorEntry entry : prepared) {
                transaction.set(userDocument.collection("authenticatorEntries").document(entry.getId().toString()),
                        FirestoreAuthenticatorEntryRepository.toDocument(entry));
            }
            long next = FirestoreLockSettingsRepository.revision(profile) + 1;
            Map<String, Object> fields = FirestoreLockSettingsRepository.lockFields(lock);
            fields.put(FirestoreLockSettingsRepository.REVISION, next);
            fields.put(FirestoreLockSettingsRepository.ENTRY_COUNT, (long) documents.size());
            transaction.set(userDocument, fields, SetOptions.merge());
            return next;
        }));
        return new Result(new LockService.LockConfig(true, timeoutSeconds, lockOnScreenLock, wrappedKey, revision),
                prepared.stream().map(EntryService::response).toList());
    }

    public record Result(LockService.LockConfig lock, List<EntryService.EntryResponse> entries) {}

    private static <T> T await(ApiFuture<T> future) {
        return dev.authsync.config.FirestoreCalls.await(future, "Key rotation");
    }
}
