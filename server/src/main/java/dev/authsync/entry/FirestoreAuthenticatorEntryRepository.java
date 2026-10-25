package dev.authsync.entry;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import dev.authsync.lock.FirestoreLockSettingsRepository;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutionException;

@Repository
public class FirestoreAuthenticatorEntryRepository implements AuthenticatorEntryRepository {
    private static final String USERS = "users";
    private static final String ENTRIES = "authenticatorEntries";
    // Permanent UUID reservations: delta sync and delayed create retries both need to see deletions.
    private static final String DELETED = "deletedEntries";
    /** Error codes for rejected changes the client should drop instead of retrying forever. */
    static final String STALE_KEY = "STALE_KEY";
    static final String VAULT_RESET = "VAULT_RESET";
    /** The edit was made from an older version: the entry changed on another device since. */
    static final String CONFLICT = "CONFLICT";
    /** The edit was made to an entry that has been deleted since. */
    static final String DELETED_CODE = "DELETED";
    /** A new entry would exceed MAX_ENTRIES_PER_USER (clients keep it on the device instead of dropping it). */
    static final String ACCOUNT_LIMIT = "ACCOUNT_LIMIT";
    private final Firestore firestore;
    private final boolean requireEditBase;
    private final dev.authsync.config.VaultReadLimiter readLimiter;
    private static final int READ_PAGE_SIZE = 50;

    @org.springframework.beans.factory.annotation.Autowired
    public FirestoreAuthenticatorEntryRepository(Firestore firestore, dev.authsync.config.AuthSyncProperties properties) {
        this.firestore = firestore;
        this.requireEditBase = properties.requireEditBase();
        this.readLimiter = new dev.authsync.config.VaultReadLimiter(firestore);
    }

    /** Without REQUIRE_EDIT_BASE (older apps may update entries without saying which version they edited). */
    public FirestoreAuthenticatorEntryRepository(Firestore firestore) {
        this.firestore = firestore;
        this.requireEditBase = false;
        this.readLimiter = new dev.authsync.config.VaultReadLimiter(firestore);
    }

    @Override
    public Instant synchronizationTime(String subject, Instant fallback) {
        var readTime = await(firestore.collection(USERS).document(subject).get()).getReadTime();
        return Instant.ofEpochSecond(readTime.getSeconds(), readTime.getNanos());
    }

    @Override
    public List<AuthenticatorEntry> findAllByGoogleSubject(String subject) {
        readLimiter.reserve(subject, EntryService.MAX_ENTRIES_PER_USER+1, true);
        var documents=await(entries(subject).limit(EntryService.MAX_ENTRIES_PER_USER+1).get()).getDocuments();
        if(documents.size()>EntryService.MAX_ENTRIES_PER_USER)throw new IllegalStateException("Vault exceeds the supported account limit");
        return documents.stream()
                .filter(FirestoreAuthenticatorEntryRepository::isCurrentSchema)
                .map(document -> fromDocument(subject, document))
                .sorted(Comparator.comparing(AuthenticatorEntry::getCreatedAt).thenComparing(AuthenticatorEntry::getId))
                .toList();
    }

    @Override
    public AuthenticatorEntry save(AuthenticatorEntry entry, AuthenticatedUser user) {
        return save(entry, user, null);
    }

    @Override
    public AuthenticatorEntry save(AuthenticatorEntry entry, AuthenticatedUser user, UUID baseMutationId) {
        BatchResult result = applyBatch(user, List.of(new Mutation(entry.getId(), entry, baseMutationId)));
        if (result.error() != null) throw rejection(result);
        return result.results().get(0); // the stored copy after an idempotent retry, as before
    }

    @Override
    public BatchResult applyBatch(AuthenticatedUser user, List<Mutation> mutations) {
        if (mutations.isEmpty()) return new BatchResult(0, null, List.of());
        String subject = user.googleSubject();
        DocumentReference userDocument = firestore.collection(USERS).document(subject);
        for (Mutation mutation : mutations) {
            if (mutation.entry() != null && !mutation.entry().getGoogleSubject().equals(subject)) {
                throw new IllegalArgumentException("Entry owner and authenticated user must match");
            }
        }
        return await(firestore.runTransaction(transaction -> {
            Map<String, DocumentReference> references = new LinkedHashMap<>();
            references.put(userDocument.getPath(), userDocument);
            for (Mutation mutation : mutations) {
                DocumentReference reference = entries(subject).document(mutation.id().toString());
                references.putIfAbsent(reference.getPath(), reference);
                DocumentReference deletion = userDocument.collection(DELETED).document(mutation.id().toString());
                references.putIfAbsent(deletion.getPath(), deletion);
            }
            Map<String, DocumentSnapshot> snapshots = new HashMap<>();
            for (DocumentSnapshot snapshot : transaction.getAll(references.values().toArray(DocumentReference[]::new)).get()) {
                snapshots.put(snapshot.getReference().getPath(), snapshot);
            }
            DocumentSnapshot profile = snapshots.get(userDocument.getPath());
            // The account count lives on the user document and changes in this same transaction, so two
            // concurrent saves cannot both pass the limit. Accounts created before the count existed are
            // counted once here (all reads happen before any write) and the count is stored from then on.
            Long storedCount = profile != null && profile.exists() ? profile.getLong(FirestoreLockSettingsRepository.ENTRY_COUNT) : null;
            long initialCount = storedCount != null ? storedCount : transaction.get(entries(subject)).get().size();
            if (FirestoreLockSettingsRepository.resetRunning(profile) || FirestoreLockSettingsRepository.resetWithoutKey(profile)
                    || user.vaultGeneration() != FirestoreLockSettingsRepository.generation(profile)) {
                return new BatchResult(0, "This vault was reset on another device. Sign in again.", List.of(), VAULT_RESET);
            }
            // A new account must use the current key version: after a recovery-key rotation, an account added
            // offline with the old key could not be read by any device.
            Long keyVersion = FirestoreLockSettingsRepository.wrappedKeyVersion(profile);
            // State of each entry as the batch progresses (null = absent), so later changes in the same batch see earlier ones.
            Map<UUID, AuthenticatorEntry> current = new HashMap<>();
            Map<UUID, Boolean> present = new HashMap<>();
            Set<UUID> deleted = new HashSet<>();
            for (Mutation mutation : mutations) {
                DocumentSnapshot marker = snapshots.get(userDocument.collection(DELETED).document(mutation.id().toString()).getPath());
                if (marker != null && marker.exists()) deleted.add(mutation.id());
            }
            long count = initialCount;
            int applied = 0;
            String error = null;
            String errorCode = null;
            List<Runnable> writes = new ArrayList<>();
            List<AuthenticatorEntry> results = new ArrayList<>();
            boolean updateProfile = false;
            Instant profileUpdatedAt = null;
            for (Mutation mutation : mutations) {
                DocumentReference entryDocument = entries(subject).document(mutation.id().toString());
                if (!present.containsKey(mutation.id())) {
                    DocumentSnapshot snapshot = snapshots.get(entryDocument.getPath());
                    boolean exists = snapshot != null && snapshot.exists();
                    present.put(mutation.id(), exists);
                    current.put(mutation.id(), exists && isCurrentSchema(snapshot) ? fromDocument(subject, snapshot) : null);
                }
                AuthenticatorEntry stored = current.get(mutation.id());
                boolean documentExists = present.get(mutation.id());
                if (mutation.entry() == null) {
                    // Delete: idempotent; permanently reserves the UUID and feeds delta sync.
                    DocumentReference deletion = userDocument.collection(DELETED).document(mutation.id().toString());
                    writes.add(() -> {
                        transaction.delete(entryDocument);
                        transaction.set(deletion, deletionRecord());
                    });
                    if (documentExists) count--;
                    present.put(mutation.id(), false);
                    current.put(mutation.id(), null);
                    deleted.add(mutation.id());
                    results.add(null);
                    applied++;
                    continue;
                }
                AuthenticatorEntry entry = mutation.entry();
                // A create's response may have been lost before another device deleted it. Replaying that
                // original UUID must not bring it back, including after a full sync or inside this batch.
                if (deleted.contains(mutation.id())) {
                    error = "This account was removed on another device, so the change was discarded.";
                    errorCode = DELETED_CODE;
                    break;
                }
                if (stored != null && stored.getMutationId().equals(entry.getMutationId())) { results.add(stored); applied++; continue; } // retry of an applied change
                // An edit names the version it was made from. If the entry changed or disappeared since (another
                // device, or a delayed upload arriving late), it is refused instead of overwriting the newer state.
                UUID base = mutation.baseMutationId();
                if (base != null && !documentExists) {
                    error = "This account was removed on another device, so the change was discarded.";
                    errorCode = DELETED_CODE;
                    break;
                }
                if (base != null && stored != null && !stored.getMutationId().equals(base)) {
                    error = "This account was changed on another device at the same time. The newer version was kept.";
                    errorCode = CONFLICT;
                    break;
                }
                // An update without a base (apps from before this rule) could overwrite a newer edit. It is refused
                // with STALE_KEY, which those apps already handle by dropping the change and showing this message.
                if (base == null && stored != null && requireEditBase) {
                    error = "This version of Lockstep is out of date and cannot save changes to existing accounts safely. Update it, then make the change again.";
                    errorCode = STALE_KEY;
                    break;
                }
                if (stored != null && stored.getKeyVersion() > entry.getKeyVersion()) {
                    error = "A stale key version cannot replace a rotated authenticator entry";
                    errorCode = STALE_KEY;
                    break;
                }
                if (stored == null && keyVersion != null && entry.getKeyVersion() < keyVersion) {
                    error = "Your recovery key was changed on another device, so an account added with the old key could not be saved. Unlock Lockstep and add it again.";
                    errorCode = STALE_KEY;
                    break;
                }
                if (!documentExists && count >= EntryService.MAX_ENTRIES_PER_USER) {
                    error = "You can store at most " + EntryService.MAX_ENTRIES_PER_USER + " authenticator accounts";
                    errorCode = ACCOUNT_LIMIT;
                    break;
                }
                if (profileUpdatedAt == null && profileNeedsUpdate(profile, user)) {
                    updateProfile = true;
                    profileUpdatedAt = entry.getUpdatedAt();
                }
                Map<String, Object> document = toDocument(entry);
                writes.add(() -> {
                    transaction.set(entryDocument, document);
                });
                if (!documentExists) count++;
                present.put(mutation.id(), true);
                current.put(mutation.id(), entry);
                results.add(entry);
                applied++;
            }
            // One write to the user document: the profile (only when missing or changed, as before) and the
            // account count (when it changed, or to store it the first time for an existing account).
            Map<String, Object> userFields = updateProfile ? toUserDocument(user, profileUpdatedAt) : new HashMap<>();
            boolean profileExists = profile != null && profile.exists();
            if (count != initialCount || storedCount == null && (profileExists || updateProfile)) {
                userFields.put(FirestoreLockSettingsRepository.ENTRY_COUNT, Math.max(0, count));
            }
            // Commit the notification marker with the data, including edits whose account count stays equal.
            if (!writes.isEmpty() || !userFields.isEmpty()) userFields.put("changeSequence", FieldValue.increment(1));
            if (!userFields.isEmpty()) writes.add(() -> transaction.set(userDocument, userFields, SetOptions.merge()));
            writes.forEach(Runnable::run);
            return new BatchResult(applied, error, results, errorCode);
        }));
    }

    @Override
    public void deleteByIdAndGoogleSubject(UUID id, String subject) {
        deleteByIdAndUser(id, new AuthenticatedUser(subject, null, null));
    }

    @Override
    public void deleteByIdAndUser(UUID id, AuthenticatedUser user) {
        // The authenticated subject selects the collection; guessed UUIDs can never cross tenant boundaries.
        // Runs as a one-change batch so the account count stays correct.
        BatchResult result = applyBatch(user, List.of(new Mutation(id, null)));
        if (result.error() != null) throw rejection(result);
    }

    private static IllegalArgumentException rejection(BatchResult result) {
        return result.errorCode() != null ? new RejectedChangeException(result.error(), result.errorCode()) : new IllegalArgumentException(result.error());
    }

    @Override
    public ChangeSet findChangedSince(String subject, Instant since) {
        Timestamp after = timestamp(since);
        // Almost every delta fits in the first page of both queries: reserve those two pages in one budget
        // transaction instead of one each (further pages are still reserved one by one before they are read).
        readLimiter.reserve(subject,2*READ_PAGE_SIZE,false);
        var changed=readPages(subject,entries(subject).whereGreaterThan("updatedAt",after).orderBy("updatedAt").orderBy(FieldPath.documentId()),true);
        if(changed==null)return new ChangeSet(findAllByGoogleSubject(subject),List.of(),true);
        var deleted=readPages(subject,firestore.collection(USERS).document(subject).collection(DELETED)
                .whereGreaterThan("deletedAt",after).orderBy("deletedAt").orderBy(FieldPath.documentId()),true);
        if(deleted==null)return new ChangeSet(findAllByGoogleSubject(subject),List.of(),true);
        List<AuthenticatorEntry> changedEntries = changed.stream()
                .filter(FirestoreAuthenticatorEntryRepository::isCurrentSchema)
                .map(document -> fromDocument(subject, document))
                .sorted(Comparator.comparing(AuthenticatorEntry::getCreatedAt).thenComparing(AuthenticatorEntry::getId))
                .toList();
        List<UUID> deletedIds = deleted.stream()
                .map(document -> UUID.fromString(document.getId())).toList();
        return new ChangeSet(changedEntries, deletedIds);
    }

    /** Reserve each page before its read. Large deltas fall back to a complete list instead of truncating. */
    private List<QueryDocumentSnapshot> readPages(String subject, Query query, boolean firstPageReserved) {
        List<QueryDocumentSnapshot> result=new ArrayList<>();
        boolean reserved=firstPageReserved;
        while(result.size()<EntryService.MAX_ENTRIES_PER_USER) {
            if(!reserved)readLimiter.reserve(subject,READ_PAGE_SIZE,false);
            reserved=false;
            var page=await(query.limit(READ_PAGE_SIZE).get()).getDocuments();
            result.addAll(page);
            if(page.size()<READ_PAGE_SIZE)return result;
            query=query.startAfter(page.get(page.size()-1));
        }
        return null;
    }

    private CollectionReference entries(String subject) {
        return firestore.collection(USERS).document(subject).collection(ENTRIES);
    }

    private static Map<String, Object> deletionRecord() {
        return Map.of("deletedAt", FieldValue.serverTimestamp(), "schemaVersion", 2);
    }

    private static boolean profileNeedsUpdate(DocumentSnapshot profile, AuthenticatedUser user) {
        if (profile == null || !profile.exists()) return true;
        if (!user.googleSubject().equals(profile.getString("googleSubject"))) return true;
        if (user.email() != null && !user.email().equals(profile.getString("email"))) return true;
        if (user.displayName() != null && !user.displayName().equals(profile.getString("displayName"))) return true;
        if (profile.getTimestamp("profileUpdatedAt") == null) return true;
        Long schemaVersion = profile.getLong("schemaVersion");
        return schemaVersion == null || schemaVersion != 2L;
    }

    private static Map<String, Object> toUserDocument(AuthenticatedUser user, Instant updatedAt) {
        Map<String, Object> document = new HashMap<>();
        document.put("googleSubject", user.googleSubject());
        if (user.email() != null) document.put("email", user.email());
        if (user.displayName() != null) document.put("displayName", user.displayName());
        document.put("profileUpdatedAt", timestamp(updatedAt));
        document.put("schemaVersion", 2);
        return document;
    }

    /** Firestore fields for an entry (also used by the atomic key rotation). */
    public static Map<String, Object> toDocument(AuthenticatorEntry entry) {
        Map<String, Object> document = new HashMap<>();
        document.put("issuer", entry.getIssuer());
        document.put("accountName", entry.getAccountName());
        document.put("encryptedSecret", Blob.fromBytes(entry.getEncryptedSecret()));
        document.put("secretIv", Blob.fromBytes(entry.getSecretIv()));
        document.put("keyVersion", entry.getKeyVersion());
        document.put("algorithm", entry.getAlgorithm());
        document.put("digits", entry.getDigits());
        document.put("periodSeconds", entry.getPeriodSeconds());
        document.put("createdAt", timestamp(entry.getCreatedAt()));
        document.put("updatedAt", FieldValue.serverTimestamp());
        document.put("mutationId", entry.getMutationId().toString());
        if (entry.getEncryptedLabel() != null) {
            document.put("encryptedLabel", Blob.fromBytes(entry.getEncryptedLabel()));
            document.put("labelIv", Blob.fromBytes(entry.getLabelIv()));
        }
        document.put("schemaVersion", 2);
        return document;
    }

    public static AuthenticatorEntry fromDocument(String subject, DocumentSnapshot document) {
        Blob encrypted = required(document.getBlob("encryptedSecret"), "encryptedSecret", document);
        Blob iv = required(document.getBlob("secretIv"), "secretIv", document);
        Timestamp created = required(document.getTimestamp("createdAt"), "createdAt", document);
        Timestamp updated = required(document.getTimestamp("updatedAt"), "updatedAt", document);
        Long version = required(document.getLong("keyVersion"), "keyVersion", document);
        Long digits = required(document.getLong("digits"), "digits", document);
        Long period = required(document.getLong("periodSeconds"), "periodSeconds", document);
        Blob label = document.getBlob("encryptedLabel");
        Blob labelIv = document.getBlob("labelIv");
        return new AuthenticatorEntry(UUID.fromString(document.getId()), subject,
                required(document.getString("issuer"), "issuer", document),
                required(document.getString("accountName"), "accountName", document),
                encrypted.toBytes(), iv.toBytes(), Math.toIntExact(version),
                required(document.getString("algorithm"), "algorithm", document),
                Math.toIntExact(digits), Math.toIntExact(period), instant(created), instant(updated),
                UUID.fromString(required(document.getString("mutationId"), "mutationId", document)),
                label == null || labelIv == null ? null : label.toBytes(), label == null || labelIv == null ? null : labelIv.toBytes());
    }

    public static boolean isCurrentSchema(DocumentSnapshot document) {
        Long schemaVersion = document.getLong("schemaVersion");
        return schemaVersion != null && schemaVersion == 2L;
    }

    private static Instant instant(Timestamp value) { return Instant.ofEpochSecond(value.getSeconds(), value.getNanos()); }
    private static Timestamp timestamp(Instant value) { return Timestamp.ofTimeSecondsAndNanos(value.getEpochSecond(), value.getNano()); }

    private static <T> T required(T value, String field, DocumentSnapshot document) {
        if (value == null) throw new IllegalStateException("Firestore document " + document.getReference().getPath() + " is missing required field " + field);
        return value;
    }

    private static <T> T await(ApiFuture<T> future) {
        return dev.authsync.config.FirestoreCalls.await(future, "Firestore operation");
    }
}
