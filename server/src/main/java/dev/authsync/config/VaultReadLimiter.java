package dev.authsync.config;

import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.SetOptions;
import dev.authsync.lock.FirestoreLockSettingsRepository;
import dev.authsync.vault.VaultResettingException;
import java.time.Clock;
import java.util.Map;

/** Shared per-account reservations, committed before bounded vault queries on any API instance. */
public final class VaultReadLimiter {
    public static final int MAX_UNITS = 20_000;
    public static final int MAX_FULL_SNAPSHOTS = 8;
    private static final long WINDOW_MILLIS = 60_000;
    private final Firestore firestore;
    private final Clock clock;

    public VaultReadLimiter(Firestore firestore) { this(firestore, Clock.systemUTC()); }
    public VaultReadLimiter(Firestore firestore, Clock clock) { this.firestore=firestore;this.clock=clock; }

    public void reserve(String subject, int units, boolean full) {
        var user=firestore.collection("users").document(subject);
        var budget=user.collection("readBudgets").document("vault");
        FirestoreCalls.await(firestore.runTransaction(transaction->{
            var profile=transaction.get(user).get();
            if(FirestoreLockSettingsRepository.resetRunning(profile))throw new VaultResettingException();
            var previous=transaction.get(budget).get();
            long now=clock.millis();
            Long started=previous.exists()?previous.getLong("windowStart"):null;
            boolean active=started!=null && now-started<WINDOW_MILLIS;
            long used=active?value(previous.getLong("units")):0;
            long snapshots=active?value(previous.getLong("fullSnapshots")):0;
            if(used+units>MAX_UNITS || full && snapshots>=MAX_FULL_SNAPSHOTS)
                throw new OperationRateLimiter.RateLimitedException("Too many vault reads. Wait a minute and try again.");
            transaction.set(budget,Map.of("windowStart",active?started:now,"units",used+units,
                    "fullSnapshots",snapshots+(full?1:0)),SetOptions.merge());
            return null;
        }),"Vault read budget");
    }
    private static long value(Long number) { return number==null?0:Math.max(0,number); }
}
