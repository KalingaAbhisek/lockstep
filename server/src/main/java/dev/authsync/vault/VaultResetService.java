package dev.authsync.vault;

import com.google.api.core.ApiFuture;
import com.google.cloud.Timestamp;
import com.google.cloud.firestore.CollectionReference;
import com.google.cloud.firestore.DocumentReference;
import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.Firestore;
import dev.authsync.lock.FirestoreLockSettingsRepository;
import dev.authsync.session.ClientSessionService;
import org.springframework.stereotype.Service;

import java.time.Clock;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.List;

/**
 * Deletes a whole vault in steps that are safe against requests running at the same time:
 * 1. one transaction replaces the user document with a reset marker ("in progress", new vault revision),
 *    so saves, rotations and passphrase changes already in flight fail instead of re-creating data;
 * 2. the stored sessions are deleted first, so no device keeps working on the old vault;
 * 3. entries and deletion records are deleted; 4. the marker is set to "complete".
 * While a reset is in progress, sign-in and passphrase setup are refused (409 VAULT_RESETTING). A reset
 * that was interrupted (for example, the server instance stopped) is finished by the next sign-in.
 */
@Service
public class VaultResetService {
    private final Firestore firestore;
    private final ClientSessionService sessions;
    private final Clock clock;

    public VaultResetService(Firestore firestore, ClientSessionService sessions, Clock clock) {
        this.firestore = firestore;
        this.sessions = sessions;
        this.clock = clock;
    }

    public void reset(String subject) {
        reset(subject, null);
    }

    public void reset(String subject, Long expectedGeneration) {
        DocumentReference user = user(subject);
        String lease = UUID.randomUUID().toString();
        await(firestore.runTransaction(transaction -> {
            DocumentSnapshot document = transaction.get(user).get();
            if (expectedGeneration != null && expectedGeneration != FirestoreLockSettingsRepository.generation(document)) throw new VaultChangedException("This vault was reset. Sign in again before making changes.");
            if (resetStillRunning(document)) throw new VaultResettingException();
            Map<String, Object> marker = new HashMap<>();
            marker.put(FirestoreLockSettingsRepository.REVISION, FirestoreLockSettingsRepository.revision(document) + 1);
            marker.put(FirestoreLockSettingsRepository.GENERATION, FirestoreLockSettingsRepository.generation(document) + 1);
            marker.put(FirestoreLockSettingsRepository.RESET_AT, Timestamp.now());
            marker.put(FirestoreLockSettingsRepository.RESET_STATUS, FirestoreLockSettingsRepository.RESET_IN_PROGRESS);
            marker.put(FirestoreLockSettingsRepository.RESET_LEASE, lease);
            transaction.set(user, marker); // replaces the profile, lock settings and wrapped key
            return null;
        }));
        cleanUp(subject, lease);
    }

    /**
     * Called before a sign-in creates a session: waits for a running reset, finishes an interrupted one. Only one
     * request takes over an interrupted cleanup (it claims a new lease in a transaction); others get 409 until
     * it is done, so no cleanup can still be deleting while a new vault is being set up.
     */
    public void beforeSignIn(String subject) {
        DocumentSnapshot document = await(user(subject).get());
        if (FirestoreLockSettingsRepository.resetInProgress(document, clock.instant())) throw new VaultResettingException();
        if (!FirestoreLockSettingsRepository.resetInterrupted(document, clock.instant())) return;
        String lease = claimInterruptedReset(subject);
        cleanUp(subject, lease);
    }

    /** Takes over an interrupted reset, or throws VaultResettingException when another request already did. */
    private String claimInterruptedReset(String subject) {
        DocumentReference user = user(subject);
        String lease = UUID.randomUUID().toString();
        boolean claimed = await(firestore.runTransaction(transaction -> {
            DocumentSnapshot current = transaction.get(user).get();
            if (!FirestoreLockSettingsRepository.resetInterrupted(current, clock.instant())) return false;
            Map<String, Object> update = new HashMap<>();
            update.put(FirestoreLockSettingsRepository.RESET_AT, Timestamp.now());
            update.put(FirestoreLockSettingsRepository.RESET_LEASE, lease);
            transaction.update(user, update);
            return true;
        }));
        if (!claimed) {
            // Someone else claimed it (or finished it) in the meantime.
            DocumentSnapshot now = await(user.get());
            if (resetStillRunning(now)) throw new VaultResettingException();
            return null;
        }
        return lease;
    }

    private boolean resetStillRunning(DocumentSnapshot document) {
        return document != null && document.exists()
                && FirestoreLockSettingsRepository.RESET_IN_PROGRESS.equals(document.getString(FirestoreLockSettingsRepository.RESET_STATUS));
    }

    private void cleanUp(String subject, String lease) {
        if (lease == null) return;
        long deadline=System.nanoTime()+java.time.Duration.ofSeconds(25).toNanos();
        DocumentReference user = user(subject);
        if (!deleteCollection(subject, lease, user.collection("clientSessions"), deadline)) throw new VaultResettingException();
        sessions.forget(subject); // and drop this instance's cached copies
        for (CollectionReference collection : enumerate(() -> user.listCollections(), Integer.MAX_VALUE, deadline)) {
            if (!deleteCollection(subject, lease, collection, deadline)) throw new VaultResettingException();
        }
        // Marked complete only by the request holding the current lease (one that took longer than
        // RESET_STALE_AFTER may have been replaced by another sign-in; that one completes it).
        boolean completed = awaitCleanup(firestore.runTransaction(transaction -> {
            DocumentSnapshot current = transaction.get(user).get();
            if (lease.equals(current.getString(FirestoreLockSettingsRepository.RESET_LEASE))
                    && FirestoreLockSettingsRepository.RESET_IN_PROGRESS.equals(current.getString(FirestoreLockSettingsRepository.RESET_STATUS))) {
                transaction.update(user, FirestoreLockSettingsRepository.RESET_STATUS, FirestoreLockSettingsRepository.RESET_COMPLETE);
                return true;
            }
            return false;
        }),deadline);
        if (!completed) throw new VaultResettingException();
    }

    private boolean deleteCollection(String subject, String lease, CollectionReference collection, long deadline) {
        while (true) {
            // listDocuments includes missing parent documents with surviving subcollections; a normal
            // query would skip them and leave old secrets behind after a reset.
            List<DocumentReference> documents = enumerate(() -> collection.listDocuments(), 100, deadline);
            if (documents.isEmpty()) return true;
            // Current vault collections are flat. Also clean any nested collections left by older schemas.
            for (DocumentReference document : documents) {
                for (CollectionReference child : enumerate(() -> document.listCollections(), Integer.MAX_VALUE, deadline)) {
                    if (!deleteCollection(subject, lease, child, deadline)) return false;
                }
            }
            if (!deleteBatch(subject, lease, documents, deadline)) return false;
        }
    }

    // Isolate blocking SDK iterators on interruptible daemon virtual threads; never wait on executor close.
    static <T> List<T> enumerate(java.util.concurrent.Callable<Iterable<T>> source, int limit, long deadline) {
        long remaining=deadline-System.nanoTime();
        if(remaining<=0)throw new dev.authsync.config.FirestoreCalls.DatabaseUnavailableException("Vault cleanup deadline reached",null);
        var task=new java.util.concurrent.FutureTask<List<T>>(() -> {
            List<T> result=new ArrayList<>();
            for(T item:source.call()) {
                if(Thread.currentThread().isInterrupted() || System.nanoTime()>=deadline)throw new InterruptedException("Cleanup interrupted");
                result.add(item);if(result.size()>=limit)break;
            }
            return result;
        });
        Thread.startVirtualThread(task);
        try { return task.get(remaining,java.util.concurrent.TimeUnit.NANOSECONDS); }
        catch(Exception error) {
            task.cancel(true);
            if(error instanceof InterruptedException)Thread.currentThread().interrupt();
            throw new dev.authsync.config.FirestoreCalls.DatabaseUnavailableException("Vault enumeration did not complete",error);
        }
    }

    // The lease and each group of deletes commit atomically. A timed-out/old worker can never delete a
    // fresh vault after a takeover: its user-document read conflicts with the new owner's lease/completion.
    boolean deleteBatch(String subject, String lease, List<DocumentReference> documents) {
        return deleteBatch(subject,lease,documents,System.nanoTime()+java.time.Duration.ofSeconds(25).toNanos());
    }
    private boolean deleteBatch(String subject, String lease, List<DocumentReference> documents,long deadline) {
        DocumentReference user = user(subject);
        return awaitCleanup(firestore.runTransaction(transaction -> {
            DocumentSnapshot current = transaction.get(user).get();
            if (!lease.equals(current.getString(FirestoreLockSettingsRepository.RESET_LEASE)) || !resetStillRunning(current)) return false;
            documents.forEach(transaction::delete);
            // Renew while progressing so a large vault is not mistaken for an interrupted cleanup.
            transaction.update(user, FirestoreLockSettingsRepository.RESET_AT, Timestamp.now());
            return true;
        }),deadline);
    }

    private static <T> T awaitCleanup(ApiFuture<T> future,long deadline) {
        long remaining=deadline-System.nanoTime();
        if(remaining<=0){future.cancel(true);throw new dev.authsync.config.FirestoreCalls.DatabaseUnavailableException("Cleanup deadline reached",null);}
        return dev.authsync.config.FirestoreCalls.await(future,"Vault cleanup",java.time.Duration.ofNanos(remaining));
    }

    private DocumentReference user(String subject) { return firestore.collection("users").document(subject); }

    private static <T> T await(ApiFuture<T> future) {
        return dev.authsync.config.FirestoreCalls.await(future, "Vault reset");
    }
}
