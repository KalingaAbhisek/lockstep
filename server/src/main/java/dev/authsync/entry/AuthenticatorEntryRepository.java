package dev.authsync.entry;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Persistence port implemented by the active storage adapter. */
public interface AuthenticatorEntryRepository {
    default Instant synchronizationTime(String subject, Instant fallback) { return fallback; }
    List<AuthenticatorEntry> findAllByGoogleSubject(String googleSubject);
    AuthenticatorEntry save(AuthenticatorEntry entry, AuthenticatedUser user);
    /**
     * Saves an edit made from the stored version {@code baseMutationId}: refused with CONFLICT when the entry
     * changed since, or DELETED when it no longer exists. {@code null} means a new entry (no precondition).
     */
    default AuthenticatorEntry save(AuthenticatorEntry entry, AuthenticatedUser user, UUID baseMutationId) { return save(entry, user); }
    void deleteByIdAndGoogleSubject(UUID id, String googleSubject);
    default void deleteByIdAndUser(UUID id, AuthenticatedUser user) { deleteByIdAndGoogleSubject(id, user.googleSubject()); }
    /** Entries updated after {@code since}, and IDs of entries deleted after it. */
    ChangeSet findChangedSince(String googleSubject, Instant since);

    record ChangeSet(List<AuthenticatorEntry> changed, List<UUID> deletedIds, boolean full) {
        public ChangeSet(List<AuthenticatorEntry> changed, List<UUID> deletedIds) { this(changed,deletedIds,false); }
    }

    /**
     * Applies changes in order inside one transaction: entries are written (PUT, {@code entry} set) or
     * deleted ({@code entry} null). Stops at the first rejected change and writes only the ones before it.
     */
    BatchResult applyBatch(AuthenticatedUser user, List<Mutation> mutations);

    /** {@code baseMutationId}: for a PUT, the mutation the client's edit was based on (null for a new entry or an older client). */
    record Mutation(UUID id, AuthenticatorEntry entry, UUID baseMutationId) {
        public Mutation(UUID id, AuthenticatorEntry entry) { this(id, entry, null); }
    }
    /**
     * {@code results}: stored entry for each applied change (null for a deletion). {@code errorCode}: a
     * machine-readable reason for {@code error} (STALE_KEY, VAULT_RESET, CONFLICT, DELETED) or null.
     */
    record BatchResult(int applied, String error, List<AuthenticatorEntry> results, String errorCode) {
        public BatchResult(int applied, String error, List<AuthenticatorEntry> results) { this(applied, error, results, null); }
    }
}

