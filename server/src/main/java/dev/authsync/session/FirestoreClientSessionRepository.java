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
        await(firestore.collection("users").document(googleSubject)
                .collection("clientSessions").document(clientType.value())
                .set(Map.of(
                        "tokenHash", session.tokenHash(),
                        "email", session.email(),
                        "displayName", session.displayName(),
                        "expiresAt", Timestamp.ofTimeSecondsAndNanos(session.expiresAt().getEpochSecond(), session.expiresAt().getNano()),
                        "updatedAt", Timestamp.now(),
                        "schemaVersion", 2)));
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
                Instant.ofEpochSecond(expiresAt.getSeconds(),expiresAt.getNanos())));
    }

    private static <T> T await(com.google.api.core.ApiFuture<T> future) {
        try { return future.get(); }
        catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Client session operation was interrupted", exception);
        } catch (ExecutionException exception) {
            if (exception.getCause() instanceof RuntimeException runtime) throw runtime;
            throw new IllegalStateException("Client session operation failed", exception.getCause());
        }
    }
}
