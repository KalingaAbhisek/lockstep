package dev.authsync.lock;

import java.util.Optional;

public interface LockSettingsRepository {
    Optional<LockSettings> find(String googleSubject);
    void save(String googleSubject, LockSettings settings);
    void delete(String googleSubject);
    /** Removes a passkey verifier stored by older versions; lock preferences are kept. */
    void deleteLegacyVerifier(String googleSubject);

    /** Whether the account exists plus its lock settings and vault revision. Implementations may read all in one lookup. */
    default AccountLock findAccount(String googleSubject) {
        Optional<LockSettings> settings = find(googleSubject);
        return new AccountLock(settings.isPresent(), settings, 0);
    }

    /**
     * Saves lock settings and returns the vault revision afterwards. The revision is a server-side counter
     * that changes whenever the wrapped vault key changes. With {@code expectedRevision} the save is refused
     * ({@link dev.authsync.vault.VaultChangedException}) when the stored revision differs, and a wrapped key
     * older than the stored one is always refused. Implementations without revisions just save.
     */
    default long saveChecked(String googleSubject, LockSettings settings, Long expectedRevision) {
        return saveChecked(googleSubject, settings, expectedRevision, true);
    }

    /**
     * {@code recentSignIn}: the request carries a Google sign-in from the last few minutes. Replacing an
     * existing wrapped key requires it.
     */
    default long saveChecked(String googleSubject, LockSettings settings, Long expectedRevision, boolean recentSignIn) {
        save(googleSubject, settings);
        return 0;
    }
    default long saveChecked(String subject, LockSettings settings, Long revision, boolean recentSignIn, Long generation) {
        return saveChecked(subject, settings, revision, recentSignIn);
    }

    record AccountLock(boolean exists, Optional<LockSettings> settings, long revision) {
        public AccountLock(boolean exists, Optional<LockSettings> settings) { this(exists, settings, 0); }
    }
}
