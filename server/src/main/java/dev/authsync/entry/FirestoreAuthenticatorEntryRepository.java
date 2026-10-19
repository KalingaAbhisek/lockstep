package dev.authsync.entry;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutionException;

@Repository
public class FirestoreAuthenticatorEntryRepository implements AuthenticatorEntryRepository {
    private static final String USERS = "users";
    private static final String ENTRIES = "authenticatorEntries";
    private final Firestore firestore;

    public FirestoreAuthenticatorEntryRepository(Firestore firestore) { this.firestore = firestore; }

    @Override
    public List<AuthenticatorEntry> findAllByGoogleSubject(String subject) {
        return await(entries(subject).get()).getDocuments().stream()
                .filter(FirestoreAuthenticatorEntryRepository::isCurrentSchema)
                .map(document -> fromDocument(subject, document))
                .sorted(Comparator.comparing(AuthenticatorEntry::getCreatedAt).thenComparing(AuthenticatorEntry::getId))
                .toList();
    }

    @Override
    public AuthenticatorEntry save(AuthenticatorEntry entry, AuthenticatedUser user) {
        if (!entry.getGoogleSubject().equals(user.googleSubject())) throw new IllegalArgumentException("Entry owner and authenticated user must match");
        DocumentReference userDocument = firestore.collection(USERS).document(user.googleSubject());
        DocumentReference entryDocument = userDocument.collection(ENTRIES).document(entry.getId().toString());
        return await(firestore.runTransaction(transaction -> {
            DocumentSnapshot existing = transaction.get(entryDocument).get();
            if (existing.exists()) {
                AuthenticatorEntry stored = fromDocument(user.googleSubject(), existing);
                if (stored.getMutationId().equals(entry.getMutationId())) return stored;
                if (stored.getKeyVersion() > entry.getKeyVersion()) {
                    throw new IllegalArgumentException("A stale key version cannot replace a rotated authenticator entry");
                }
            }
            transaction.set(userDocument, toUserDocument(user, entry.getUpdatedAt()), SetOptions.merge());
            transaction.set(entryDocument, toDocument(entry));
            return entry;
        }));
    }

    @Override
    public void deleteByIdAndGoogleSubject(UUID id, String subject) {
        // The authenticated subject selects the collection; guessed UUIDs can never cross tenant boundaries.
        await(entries(subject).document(id.toString()).delete());
    }

    private CollectionReference entries(String subject) {
        return firestore.collection(USERS).document(subject).collection(ENTRIES);
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

    private static Map<String, Object> toDocument(AuthenticatorEntry entry) {
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
        document.put("updatedAt", timestamp(entry.getUpdatedAt()));
        document.put("mutationId", entry.getMutationId().toString());
        document.put("schemaVersion", 2);
        return document;
    }

    private static AuthenticatorEntry fromDocument(String subject, DocumentSnapshot document) {
        Blob encrypted = required(document.getBlob("encryptedSecret"), "encryptedSecret", document);
        Blob iv = required(document.getBlob("secretIv"), "secretIv", document);
        Timestamp created = required(document.getTimestamp("createdAt"), "createdAt", document);
        Timestamp updated = required(document.getTimestamp("updatedAt"), "updatedAt", document);
        Long version = required(document.getLong("keyVersion"), "keyVersion", document);
        Long digits = required(document.getLong("digits"), "digits", document);
        Long period = required(document.getLong("periodSeconds"), "periodSeconds", document);
        return new AuthenticatorEntry(UUID.fromString(document.getId()), subject,
                required(document.getString("issuer"), "issuer", document),
                required(document.getString("accountName"), "accountName", document),
                encrypted.toBytes(), iv.toBytes(), Math.toIntExact(version),
                required(document.getString("algorithm"), "algorithm", document),
                Math.toIntExact(digits), Math.toIntExact(period), instant(created), instant(updated),
                UUID.fromString(required(document.getString("mutationId"), "mutationId", document)));
    }

    private static boolean isCurrentSchema(DocumentSnapshot document) {
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
        try { return future.get(); }
        catch (InterruptedException exception) { Thread.currentThread().interrupt(); throw new IllegalStateException("Firestore operation was interrupted", exception); }
        catch (ExecutionException exception) {
            if (exception.getCause() instanceof RuntimeException runtime) throw runtime;
            throw new IllegalStateException("Firestore operation failed", exception.getCause());
        }
    }
}
