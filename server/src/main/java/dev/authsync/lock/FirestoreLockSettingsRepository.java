package dev.authsync.lock;

import com.google.api.core.ApiFuture;
import com.google.cloud.firestore.Blob;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.FieldValue;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.SetOptions;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.HashMap;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

@Repository
public class FirestoreLockSettingsRepository implements LockSettingsRepository {
    private final Firestore firestore;

    public FirestoreLockSettingsRepository(Firestore firestore) { this.firestore = firestore; }

    @Override
    public Optional<LockSettings> find(String googleSubject) {
        DocumentSnapshot document = await(firestore.collection("users").document(googleSubject).get());
        Blob salt = document.getBlob("lockPasscodeSalt");
        Blob verifier = document.getBlob("lockPasscodeVerifier");
        Long iterations = document.getLong("lockPasscodeIterations");
        Long timeout = document.getLong("lockTimeoutSeconds");
        Boolean lockOnScreenLock = document.getBoolean("lockOnScreenLock");
        if (salt == null || verifier == null || iterations == null || timeout == null) return Optional.empty();
        WrappedVaultKey wrappedKey = null;
        String wrappedMasterKey = document.getString("wrappedVaultKey");
        if (wrappedMasterKey != null) {
            wrappedKey = new WrappedVaultKey(
                    Math.toIntExact(document.getLong("wrappedVaultKeyVersion")),
                    document.getLong("wrappedVaultKeyCreatedAt"), document.getLong("wrappedVaultKeyUpdatedAt"),
                    document.getString("wrappedVaultKeyAlgorithm"), Math.toIntExact(document.getLong("wrappedVaultKeyIterations")),
                    document.getString("wrappedVaultKeySalt"), document.getString("wrappedVaultKeyIv"), wrappedMasterKey);
        }
        return Optional.of(new LockSettings(salt.toBytes(), verifier.toBytes(), Math.toIntExact(iterations), Math.toIntExact(timeout),
                Boolean.TRUE.equals(lockOnScreenLock), wrappedKey));
    }

    @Override
    public void save(String googleSubject, LockSettings settings) {
        Map<String, Object> values = new HashMap<>();
        values.put("lockPasscodeSalt", Blob.fromBytes(settings.salt()));
        values.put("lockPasscodeVerifier", Blob.fromBytes(settings.verifier()));
        values.put("lockPasscodeIterations", settings.iterations());
        values.put("lockTimeoutSeconds", settings.timeoutSeconds());
        values.put("lockOnScreenLock", settings.lockOnScreenLock());
        if (settings.wrappedKey() != null) {
            WrappedVaultKey key = settings.wrappedKey();
            values.put("wrappedVaultKeyVersion", key.currentVersion()); values.put("wrappedVaultKeyCreatedAt", key.createdAt());
            values.put("wrappedVaultKeyUpdatedAt", key.wrappedAt()); values.put("wrappedVaultKeyAlgorithm", key.wrapping());
            values.put("wrappedVaultKeyIterations", key.iterations()); values.put("wrappedVaultKeySalt", key.salt());
            values.put("wrappedVaultKeyIv", key.iv()); values.put("wrappedVaultKey", key.wrappedMasterKey());
        }
        await(firestore.collection("users").document(googleSubject).set(values, SetOptions.merge()));
    }

    @Override
    public void delete(String googleSubject) {
        Map<String, Object> values = new HashMap<>();
        for (String field : new String[]{"lockPasscodeSalt", "lockPasscodeVerifier", "lockPasscodeIterations", "lockTimeoutSeconds", "lockOnScreenLock",
                "wrappedVaultKeyVersion", "wrappedVaultKeyCreatedAt", "wrappedVaultKeyUpdatedAt", "wrappedVaultKeyAlgorithm",
                "wrappedVaultKeyIterations", "wrappedVaultKeySalt", "wrappedVaultKeyIv", "wrappedVaultKey"}) {
            values.put(field, FieldValue.delete());
        }
        await(firestore.collection("users").document(googleSubject).update(values));
    }

    private static <T> T await(ApiFuture<T> future) {
        try { return future.get(); }
        catch (InterruptedException exception) { Thread.currentThread().interrupt(); throw new IllegalStateException("Firestore operation was interrupted", exception); }
        catch (ExecutionException exception) { throw new IllegalStateException("Firestore operation failed", exception.getCause()); }
    }
}
