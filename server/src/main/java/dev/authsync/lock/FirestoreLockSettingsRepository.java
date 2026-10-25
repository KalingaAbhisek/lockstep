package dev.authsync.lock;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.Blob;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.FieldValue;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.SetOptions;
import com.google.cloud.Timestamp;
import dev.authsync.config.AuthSyncProperties;
import dev.authsync.config.ReauthenticationRequiredException;
import dev.authsync.vault.VaultChangedException;
import dev.authsync.vault.VaultResettingException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.time.Duration;
import java.time.Instant;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutionException;

@Repository
public class FirestoreLockSettingsRepository implements LockSettingsRepository {
    private static final String[] LEGACY_VERIFIER_FIELDS = {"lockPasscodeSalt", "lockPasscodeVerifier", "lockPasscodeIterations"};
    private static final String[] WRAPPED_KEY_FIELDS = {"wrappedVaultKeyVersion", "wrappedVaultKeyCreatedAt", "wrappedVaultKeyUpdatedAt",
            "wrappedVaultKeyAlgorithm", "wrappedVaultKeyIterations", "wrappedVaultKeySalt", "wrappedVaultKeyIv", "wrappedVaultKey",
            "wrappedVaultKeyMemoryKiB", "wrappedVaultKeyParallelism"};
    /** Server-side counter, incremented whenever the wrapped vault key changes or the vault is reset. */
    public static final String REVISION = "vaultRevision";
    public static final String GENERATION = "vaultGeneration";
    public static long generation(DocumentSnapshot document) {
        Long value = document == null || !document.exists() ? null : document.getLong(GENERATION);
        return value == null ? 0 : value;
    }
    public static boolean resetRunning(DocumentSnapshot document) {
        return document != null && document.exists() && RESET_IN_PROGRESS.equals(document.getString(RESET_STATUS));
    }
    /** Set when the vault was reset; the user document then holds only this and the revision. */
    public static final String RESET_AT = "vaultResetAt";
    /** "IN_PROGRESS" while a reset deletes the old vault, then "COMPLETE". */
    public static final String RESET_STATUS = "vaultResetStatus";
    public static final String RESET_IN_PROGRESS = "IN_PROGRESS";
    public static final String RESET_COMPLETE = "COMPLETE";
    /** Random ID of the server request currently cleaning up a reset; only that request may mark it complete. */
    public static final String RESET_LEASE = "vaultResetLease";
    /** A reset still "in progress" after this long was interrupted; the next sign-in finishes it. */
    public static final Duration RESET_STALE_AFTER = Duration.ofMinutes(5);
    /** Number of entry documents, kept up to date inside the same transaction as every entry change. */
    public static final String ENTRY_COUNT = "entryCount";
    /** Bookkeeping fields that do not by themselves mean an account exists. */
    private static final Set<String> BOOKKEEPING_FIELDS = Set.of(REVISION, GENERATION, RESET_AT, RESET_STATUS, RESET_LEASE, ENTRY_COUNT, "changeSequence");
    private final Firestore firestore;
    private final boolean requireRevision;

    @Autowired
    public FirestoreLockSettingsRepository(Firestore firestore, AuthSyncProperties properties) {
        this.firestore = firestore;
        this.requireRevision = properties.requireVaultRevision();
    }

    public FirestoreLockSettingsRepository(Firestore firestore) {
        this.firestore = firestore;
        this.requireRevision = false;
    }

    @Override
    public Optional<LockSettings> find(String googleSubject) {
        return parse(await(firestore.collection("users").document(googleSubject).get()));
    }

    @Override
    public AccountLock findAccount(String googleSubject) {
        DocumentSnapshot document = await(firestore.collection("users").document(googleSubject).get());
        return new AccountLock(accountExists(document), parse(document), revision(document));
    }

    /** The vault revision stored in a user document (0 before the first wrapped-key change). */
    public static long revision(DocumentSnapshot document) {
        Long value = document == null || !document.exists() ? null : document.getLong(REVISION);
        return value == null ? 0 : value;
    }

    /** True when the user document holds account data, not just the bookkeeping left by a vault reset. */
    public static boolean accountExists(DocumentSnapshot document) {
        if (document == null || !document.exists()) return false;
        Map<String, Object> data = document.getData();
        return data == null || data.keySet().stream().anyMatch(field -> !BOOKKEEPING_FIELDS.contains(field));
    }

    /** True while a reset is still deleting the old vault (and has not been interrupted). */
    public static boolean resetInProgress(DocumentSnapshot document, Instant now) {
        if (document == null || !document.exists() || !RESET_IN_PROGRESS.equals(document.getString(RESET_STATUS))) return false;
        Timestamp resetAt = document.getTimestamp(RESET_AT);
        return resetAt != null && Instant.ofEpochSecond(resetAt.getSeconds(), resetAt.getNanos()).isAfter(now.minus(RESET_STALE_AFTER));
    }

    /** True when a reset was interrupted before its cleanup finished. */
    public static boolean resetInterrupted(DocumentSnapshot document, Instant now) {
        return document != null && document.exists() && RESET_IN_PROGRESS.equals(document.getString(RESET_STATUS))
                && !resetInProgress(document, now);
    }

    /** True when the vault was reset and no new passphrase has been set up since. */
    public static boolean resetWithoutKey(DocumentSnapshot document) {
        return document != null && document.exists() && document.get(RESET_AT) != null && document.getString("wrappedVaultKey") == null;
    }

    /** Version of the stored wrapped vault key, or null when none is stored. */
    public static Long wrappedKeyVersion(DocumentSnapshot document) {
        if (document == null || !document.exists() || document.getString("wrappedVaultKey") == null) return null;
        return document.getLong("wrappedVaultKeyVersion");
    }

    /**
     * Refuses a wrapped key that would replace the stored one unsafely: a stale expected revision (another
     * device changed the key since this client read it) or an older key version (the vault was rotated, so
     * the older key no longer opens the stored entries).
     */
    public static void requireSafeKeyChange(DocumentSnapshot document, WrappedVaultKey key, Long expectedRevision) {
        requireSafeKeyChange(document, key, expectedRevision, false);
    }

    /**
     * {@code requireRevision} (REQUIRE_VAULT_REVISION, on by default): replacing an existing
     * wrapped key without saying which revision it expects is refused too.
     */
    public static void requireSafeKeyChange(DocumentSnapshot document, WrappedVaultKey key, Long expectedRevision, boolean requireRevision) {
        if (requireRevision && expectedRevision == null && key != null && wrappedKeyVersion(document) != null
                && !key.wrappedMasterKey().equals(document.getString("wrappedVaultKey"))) {
            throw new VaultChangedException("This version of Lockstep is out of date. Update it, then change your passphrase again.");
        }
        if (expectedRevision != null && expectedRevision != revision(document)) {
            throw new VaultChangedException("Your passphrase or recovery key changed on another device. Unlock with the current passphrase and try again.");
        }
        Long storedVersion = wrappedKeyVersion(document);
        if (key != null && storedVersion != null && key.currentVersion() < storedVersion) {
            throw new VaultChangedException("A newer recovery key is already in use on another device. Unlock with the current passphrase and try again.");
        }
    }

    @Override
    public long saveChecked(String googleSubject, LockSettings settings, Long expectedRevision, boolean recentSignIn) {
        return saveChecked(googleSubject, settings, expectedRevision, recentSignIn, null);
    }

    @Override
    public long saveChecked(String googleSubject, LockSettings settings, Long expectedRevision, boolean recentSignIn, Long expectedGeneration) {
        DocumentReference user = firestore.collection("users").document(googleSubject);
        return await(firestore.runTransaction(transaction -> {
            DocumentSnapshot document = transaction.get(user).get();
            if (resetRunning(document)) throw new VaultResettingException();
            if (expectedGeneration != null && expectedGeneration != generation(document)) throw new VaultChangedException("This vault was reset. Sign in again before making changes.");
            requireSafeKeyChange(document, settings.wrappedKey(), expectedRevision, requireRevision);
            long revision = revision(document);
            Map<String, Object> values = lockFields(settings);
            WrappedVaultKey key = settings.wrappedKey();
            boolean replacesKey = key != null && wrappedKeyVersion(document) != null && !key.wrappedMasterKey().equals(document.getString("wrappedVaultKey"));
            // Replacing an existing wrapped key (passphrase change, recovery-key import) needs a recent Google
            // sign-in; setting up the first key right after signing in does not.
            if (replacesKey && !recentSignIn) throw new ReauthenticationRequiredException();
            if (key != null && !key.wrappedMasterKey().equals(document.getString("wrappedVaultKey"))) {
                revision++;
                values.put(REVISION, revision);
            }
            transaction.set(user, values, SetOptions.merge());
            return revision;
        }));
    }

    private static Optional<LockSettings> parse(DocumentSnapshot document) {
        if (!document.exists()) return Optional.empty();
        Long timeout = document.getLong("lockTimeoutSeconds");
        if (timeout == null) return Optional.empty();
        WrappedVaultKey wrappedKey = null;
        String wrappedMasterKey = document.getString("wrappedVaultKey");
        if (wrappedMasterKey != null) {
            wrappedKey = new WrappedVaultKey(
                    Math.toIntExact(document.getLong("wrappedVaultKeyVersion")),
                    document.getLong("wrappedVaultKeyCreatedAt"), document.getLong("wrappedVaultKeyUpdatedAt"),
                    document.getString("wrappedVaultKeyAlgorithm"), Math.toIntExact(document.getLong("wrappedVaultKeyIterations")),
                    document.getString("wrappedVaultKeySalt"), document.getString("wrappedVaultKeyIv"), wrappedMasterKey,
                    toInteger(document.getLong("wrappedVaultKeyMemoryKiB")), toInteger(document.getLong("wrappedVaultKeyParallelism")));
        }
        Blob salt = document.getBlob("lockPasscodeSalt");
        Blob verifier = document.getBlob("lockPasscodeVerifier");
        Long iterations = document.getLong("lockPasscodeIterations");
        return Optional.of(new LockSettings(Math.toIntExact(timeout), Boolean.TRUE.equals(document.getBoolean("lockOnScreenLock")), wrappedKey,
                salt == null ? null : salt.toBytes(), verifier == null ? null : verifier.toBytes(),
                iterations == null ? null : Math.toIntExact(iterations)));
    }

    @Override
    public void save(String googleSubject, LockSettings settings) {
        await(firestore.collection("users").document(googleSubject).set(lockFields(settings), SetOptions.merge()));
    }

    /** Fields written for lock settings (merge into the user document); also used by the atomic key rotation. */
    public static Map<String, Object> lockFields(LockSettings settings) {
        Map<String, Object> values = new HashMap<>();
        values.put("lockTimeoutSeconds", settings.timeoutSeconds());
        values.put("lockOnScreenLock", settings.lockOnScreenLock());
        // Saving lock settings always removes any passkey verifier written by older versions.
        for (String field : LEGACY_VERIFIER_FIELDS) values.put(field, FieldValue.delete());
        if (settings.wrappedKey() != null) {
            WrappedVaultKey key = settings.wrappedKey();
            values.put("wrappedVaultKeyVersion", key.currentVersion()); values.put("wrappedVaultKeyCreatedAt", key.createdAt());
            values.put("wrappedVaultKeyUpdatedAt", key.wrappedAt()); values.put("wrappedVaultKeyAlgorithm", key.wrapping());
            values.put("wrappedVaultKeyIterations", key.iterations()); values.put("wrappedVaultKeySalt", key.salt());
            values.put("wrappedVaultKeyIv", key.iv()); values.put("wrappedVaultKey", key.wrappedMasterKey());
            // Argon2id parameters (absent for PBKDF2 keys).
            values.put("wrappedVaultKeyMemoryKiB", key.memoryKiB() == null ? FieldValue.delete() : (Object) key.memoryKiB());
            values.put("wrappedVaultKeyParallelism", key.parallelism() == null ? FieldValue.delete() : (Object) key.parallelism());
        }
        return values;
    }

    @Override
    public void delete(String googleSubject) {
        Map<String, Object> values = new HashMap<>();
        values.put("lockTimeoutSeconds", FieldValue.delete());
        values.put("lockOnScreenLock", FieldValue.delete());
        for (String field : LEGACY_VERIFIER_FIELDS) values.put(field, FieldValue.delete());
        for (String field : WRAPPED_KEY_FIELDS) values.put(field, FieldValue.delete());
        values.put(REVISION, FieldValue.increment(1)); // the wrapped key is gone
        await(firestore.collection("users").document(googleSubject).update(values));
    }

    @Override
    public void deleteLegacyVerifier(String googleSubject) {
        Map<String, Object> values = new HashMap<>();
        for (String field : LEGACY_VERIFIER_FIELDS) values.put(field, FieldValue.delete());
        await(firestore.collection("users").document(googleSubject).update(values));
    }

    private static Integer toInteger(Long value) { return value == null ? null : Math.toIntExact(value); }

    private static <T> T await(ApiFuture<T> future) {
        return dev.authsync.config.FirestoreCalls.await(future, "Firestore operation");
    }
}
