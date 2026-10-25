package dev.authsync.session;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.ExecutionException;

@Repository
public class FirestoreClientSessionRepository implements ClientSessionRepository {
    private final Firestore firestore;

    public FirestoreClientSessionRepository(Firestore firestore) { this.firestore = firestore; }

    @Override
    public void replace(String googleSubject, ClientType clientType, StoredSession session) {
        replaceChecked(googleSubject, clientType, session);
    }

    @Override
    public StoredSession replaceChecked(String subject, ClientType type, StoredSession session) {
        var user = firestore.collection("users").document(subject);
        return await(firestore.runTransaction(transaction -> {
            var current = transaction.get(user).get();
            if (dev.authsync.lock.FirestoreLockSettingsRepository.resetRunning(current)) throw new dev.authsync.vault.VaultResettingException();
            long generation = dev.authsync.lock.FirestoreLockSettingsRepository.generation(current);
            transaction.set(user.collection("clientSessions").document(type.value()), Map.of(
                    "tokenHash", session.tokenHash(), "email", session.email(), "displayName", session.displayName(),
                    "expiresAt", Timestamp.ofTimeSecondsAndNanos(session.expiresAt().getEpochSecond(), session.expiresAt().getNano()),
                    "updatedAt", Timestamp.now(), "schemaVersion", 3, "vaultGeneration", generation));
            return new StoredSession(session.tokenHash(), session.email(), session.displayName(), session.expiresAt(), generation);
        }));
    }

    @Override
    public boolean revokeChecked(String subject, ClientType type, String expectedHash, boolean all) {
        var sessions = firestore.collection("users").document(subject).collection("clientSessions");
        return await(firestore.runTransaction(transaction -> {
            var caller = transaction.get(sessions.document(type.value())).get();
            if (!caller.exists() || !expectedHash.equals(caller.getString("tokenHash"))) return false;
            for (ClientType target : all ? ClientType.values() : new ClientType[]{type}) {
                transaction.delete(sessions.document(target.value()));
            }
            return true;
        }));
    }

    @Override
    public void delete(String googleSubject, ClientType clientType) {
        await(firestore.collection("users").document(googleSubject)
                .collection("clientSessions").document(clientType.value()).delete());
    }

    @Override
    public Optional<StoredSession> find(String googleSubject, ClientType clientType) {
        DocumentSnapshot document = await(firestore.collection("users").document(googleSubject)
                .collection("clientSessions").document(clientType.value()).get());
        if(!document.exists())return Optional.empty();
        Timestamp expiresAt=document.getTimestamp("expiresAt");
        String tokenHash=document.getString("tokenHash");
        if(expiresAt==null||tokenHash==null||tokenHash.isBlank())return Optional.empty();
        return Optional.of(new StoredSession(
                tokenHash,
                String.valueOf(document.getString("email") == null ? "" : document.getString("email")),
                String.valueOf(document.getString("displayName") == null ? "" : document.getString("displayName")),
                Instant.ofEpochSecond(expiresAt.getSeconds(),expiresAt.getNanos()),
                document.getLong("vaultGeneration") == null ? 0 : document.getLong("vaultGeneration")));
    }

    private static <T> T await(com.google.api.core.ApiFuture<T> future) {
        return dev.authsync.config.FirestoreCalls.await(future, "Client session operation");
    }
}
