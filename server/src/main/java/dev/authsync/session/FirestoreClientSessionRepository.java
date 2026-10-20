package dev.authsync.session;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import org.springframework.stereotype.Repository;

import java.util.Map;
import java.util.concurrent.ExecutionException;

@Repository
public class FirestoreClientSessionRepository implements ClientSessionRepository {
    private final Firestore firestore;

    public FirestoreClientSessionRepository(Firestore firestore) { this.firestore = firestore; }

    @Override
    public void replace(String googleSubject, ClientType clientType, String tokenHash) {
        await(firestore.collection("users").document(googleSubject)
                .collection("clientSessions").document(clientType.value())
                .set(Map.of(
                        "tokenHash", tokenHash,
                        "updatedAt", Timestamp.now(),
                        "schemaVersion", 1)));
    }

    @Override
    public boolean matches(String googleSubject, ClientType clientType, String tokenHash) {
        DocumentSnapshot document = await(firestore.collection("users").document(googleSubject)
                .collection("clientSessions").document(clientType.value()).get());
        return document.exists() && tokenHash.equals(document.getString("tokenHash"));
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
