package dev.authsync.vault;

import com.google.cloud.firestore.DocumentSnapshot;
import com.google.cloud.firestore.FieldValue;
import com.google.cloud.firestore.Firestore;
import com.google.cloud.firestore.FirestoreOptions;
import dev.authsync.config.AuthSyncProperties;
import dev.authsync.entry.AuthenticatedUser;
import dev.authsync.entry.AuthenticatorEntry;
import dev.authsync.entry.AuthenticatorEntryRepository;
import dev.authsync.entry.EntryService;
import dev.authsync.entry.FirestoreAuthenticatorEntryRepository;
import dev.authsync.lock.FirestoreLockSettingsRepository;
import dev.authsync.lock.LockSettings;
import dev.authsync.lock.WrappedVaultKey;
import dev.authsync.session.ClientSessionService;
import dev.authsync.session.FirestoreClientSessionRepository;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.time.Clock;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Transaction behaviour against the real Firestore emulator (the mock API used by the browser tests cannot
 * show it). Runs only when FIRESTORE_EMULATOR_HOST is set, for example:
 *   npx firebase-tools emulators:exec --project demo-lockstep --only firestore "mvn -B -pl server -am test -Dtest=FirestoreEmulatorTest"
 */
@EnabledIfEnvironmentVariable(named = "FIRESTORE_EMULATOR_HOST", matches = ".+")
class FirestoreEmulatorTest {
    private static Firestore firestore;
    private static FirestoreAuthenticatorEntryRepository entries;
    private static FirestoreLockSettingsRepository locks;
    private static EntryService entryService;
    private static VaultRotationService rotation;

    @BeforeAll
    static void connect() {
        firestore = FirestoreOptions.newBuilder()
                .setProjectId("demo-lockstep")
                .setEmulatorHost(System.getenv("FIRESTORE_EMULATOR_HOST"))
                .build().getService();
        entries = new FirestoreAuthenticatorEntryRepository(firestore);
        locks = new FirestoreLockSettingsRepository(firestore);
        entryService = new EntryService(entries, Clock.systemUTC());
        rotation = new VaultRotationService(firestore, entryService);
    }

    @AfterAll
    static void close() throws Exception { firestore.close(); }

    @Test
    void readBudgetsAreSharedAcrossInstancesAndRefillWithoutTouchingVaultData() throws Exception {
        String subject=user().googleSubject();
        var clock=Clock.fixed(Instant.parse("2026-10-24T00:00:00Z"),java.time.ZoneOffset.UTC);
        var first=new dev.authsync.config.VaultReadLimiter(firestore,clock);
        var other=new dev.authsync.config.VaultReadLimiter(firestore,clock);
        for(int i=0;i<8;i++)first.reserve(subject,1001,true);
        assertThatThrownBy(()->other.reserve(subject,1001,true)).isInstanceOf(dev.authsync.config.OperationRateLimiter.RateLimitedException.class);
        other.reserve(subject,20_000-8008,false);
        assertThatThrownBy(()->first.reserve(subject,1,false)).isInstanceOf(dev.authsync.config.OperationRateLimiter.RateLimitedException.class);
        assertThatThrownBy(()->new dev.authsync.config.VaultReadLimiter(firestore,Clock.offset(clock,java.time.Duration.ofSeconds(-1))).reserve(subject,1,false))
                .isInstanceOf(dev.authsync.config.OperationRateLimiter.RateLimitedException.class);
        new dev.authsync.config.VaultReadLimiter(firestore,Clock.offset(clock,java.time.Duration.ofMinutes(1))).reserve(subject,1001,true);
        assertThat(firestore.collection("users").document(subject).get().get().exists()).isFalse();
    }

    @Test
    void concurrentReadReservationsCannotExceedTheSharedBudget() throws Exception {
        String subject=user().googleSubject();
        var limiter=new dev.authsync.config.VaultReadLimiter(firestore);
        limiter.reserve(subject,19_000,false);
        List<Callable<Boolean>> attempts=new ArrayList<>();
        for(int i=0;i<4;i++)attempts.add(()->{try{new dev.authsync.config.VaultReadLimiter(firestore).reserve(subject,1000,false);return true;}
            catch(dev.authsync.config.OperationRateLimiter.RateLimitedException refused){return false;}});
        try(var executor=Executors.newFixedThreadPool(4)) {
            int accepted=0;for(var result:executor.invokeAll(attempts))if(result.get())accepted++;
            assertThat(accepted).isEqualTo(1);
        }
    }

    @Test
    void largeDeletionDeltasFallBackToACompleteSnapshot() throws Exception {
        var user=user();String subject=user.googleSubject();var entry=entry(user,UUID.randomUUID(),1);entries.save(entry,user);
        var reference=firestore.collection("users").document(subject).collection("deletedEntries");
        for(int start=0;start<1001;start+=400){var batch=firestore.batch();for(int i=start;i<Math.min(1001,start+400);i++)
            batch.set(reference.document(UUID.randomUUID().toString()),Map.of("deletedAt",com.google.cloud.Timestamp.now()));batch.commit().get();}
        var result=entryService.changes(subject,Instant.now().minusSeconds(300).toEpochMilli());
        assertThat(result.full()).isTrue();assertThat(result.entries()).hasSize(1);assertThat(result.deletedIds()).isEmpty();
    }

    @Test
    void editsCommitANotificationMarkerButIdempotentRetriesDoNotRepeatIt() throws Exception {
        var user=user();String subject=user.googleSubject();var original=entry(user,UUID.randomUUID(),1);
        entries.save(original,user);
        var profile=firestore.collection("users").document(subject);
        long created=profile.get().get().getLong("changeSequence");
        var edited=entry(user,original.getId(),1);
        entries.save(edited,user,original.getMutationId());
        assertThat(profile.get().get().getLong("changeSequence")).isEqualTo(created+1);
        entries.save(edited,user,original.getMutationId());
        assertThat(profile.get().get().getLong("changeSequence")).isEqualTo(created+1);
    }

    @Test
    void delayedSignOutDoesNotDeleteNewerSessionsAndAllClientsAreRevokedTogether() throws Exception {
        String subject = user().googleSubject();
        var repository = new FirestoreClientSessionRepository(firestore);
        var service = new ClientSessionService(repository, new AuthSyncProperties("web","extension",""));
        var now = Instant.now();
        var jwt = org.springframework.security.oauth2.jwt.Jwt.withTokenValue("test").header("alg","RS256")
                .subject(subject).audience(List.of("web","extension")).issuedAt(now).expiresAt(now.plusSeconds(3600)).build();
        var old = service.register(jwt,"web");
        assertThat(service.isActive(jwt,"web",old.sessionToken())).isTrue();
        var newer = service.register(jwt,"web");
        var extension = service.register(jwt,"extension");
        assertThat(service.revoke(subject,dev.authsync.session.ClientType.WEB,true,old.sessionToken())).isFalse();
        assertThat(service.isActive(jwt,"web",newer.sessionToken())).isTrue();
        assertThat(service.isActive(jwt,"extension",extension.sessionToken())).isTrue();
        assertThat(service.revoke(subject,dev.authsync.session.ClientType.WEB,false,newer.sessionToken())).isTrue();
        assertThat(repository.find(subject,dev.authsync.session.ClientType.WEB)).isEmpty();
        assertThat(repository.find(subject,dev.authsync.session.ClientType.EXTENSION)).isPresent();
        service.register(jwt,"web");
        assertThat(service.revoke(subject,dev.authsync.session.ClientType.EXTENSION,true,extension.sessionToken())).isTrue();
        assertThat(repository.find(subject,dev.authsync.session.ClientType.WEB)).isEmpty();
        assertThat(repository.find(subject,dev.authsync.session.ClientType.EXTENSION)).isEmpty();
    }

    @Test
    void concurrentSavesCannotPassTheAccountLimit() throws Exception {
        AuthenticatedUser user = user();
        // Start one below the limit without writing 999 documents.
        firestore.collection("users").document(user.googleSubject())
                .set(Map.of("googleSubject", user.googleSubject(), "entryCount", (long) EntryService.MAX_ENTRIES_PER_USER - 1)).get();
        List<Callable<AuthenticatorEntryRepository.BatchResult>> saves = new ArrayList<>();
        for (int save = 0; save < 4; save++) {
            AuthenticatorEntry entry = entry(user, UUID.randomUUID(), 1);
            saves.add(() -> entries.applyBatch(user, List.of(new AuthenticatorEntryRepository.Mutation(entry.getId(), entry))));
        }
        int stored = 0;
        try (ExecutorService executor = Executors.newFixedThreadPool(4)) {
            for (Future<AuthenticatorEntryRepository.BatchResult> result : executor.invokeAll(saves)) {
                if (result.get().error() == null) stored++;
            }
        }
        assertThat(stored).isEqualTo(1);
        assertThat(userDocument(user).getLong("entryCount")).isEqualTo((long) EntryService.MAX_ENTRIES_PER_USER);
    }

    @Test
    void theAccountCountIsCreatedOnceForOlderAccountsAndKeptUpToDate() throws Exception {
        AuthenticatedUser user = user();
        for (int index = 0; index < 3; index++) save(user, entry(user, UUID.randomUUID(), 1));
        firestore.collection("users").document(user.googleSubject()).update("entryCount", FieldValue.delete()).get();

        UUID added = UUID.randomUUID();
        save(user, entry(user, added, 1));
        assertThat(userDocument(user).getLong("entryCount")).isEqualTo(4L);

        entries.deleteByIdAndGoogleSubject(added, user.googleSubject());
        assertThat(userDocument(user).getLong("entryCount")).isEqualTo(3L);
    }

    @Test
    void aWrappedKeyChangeWithAStaleRevisionOrOlderVersionIsRefused() throws Exception {
        String subject = user().googleSubject();
        long first = locks.saveChecked(subject, new LockSettings(300, false, key(1, 1)), null);
        long second = locks.saveChecked(subject, new LockSettings(300, false, key(1, 2)), first);
        assertThat(second).isEqualTo(first + 1);

        // A device that still has the first revision (for example a fast clock and an old key) is refused.
        assertThatThrownBy(() -> locks.saveChecked(subject, new LockSettings(300, false, key(1, 3)), first))
                .isInstanceOf(VaultChangedException.class);
        // A timeout-only change keeps the revision.
        assertThat(locks.saveChecked(subject, new LockSettings(600, false, key(1, 2)), second)).isEqualTo(second);
        // After a rotation to version 2, an old-version key is refused even without a revision (older clients).
        locks.saveChecked(subject, new LockSettings(300, false, key(2, 4)), second);
        assertThatThrownBy(() -> locks.saveChecked(subject, new LockSettings(300, false, key(1, 5)), null))
                .isInstanceOf(VaultChangedException.class);
    }

    @Test
    void rotationIsRefusedAfterAConcurrentPassphraseChangeAndCoversTheFullAccountLimit() throws Exception {
        AuthenticatedUser user = user();
        String subject = user.googleSubject();
        long revision = locks.saveChecked(subject, new LockSettings(300, false, key(1, 1)), null);
        List<AuthenticatorEntry> stored = new ArrayList<>();
        for (int index = 0; index < EntryService.MAX_ENTRIES_PER_USER; index++) stored.add(largestEntry(user, UUID.randomUUID(), 1));
        for (int start = 0; start < stored.size(); start += 50) {
            List<AuthenticatorEntryRepository.Mutation> chunk = stored.subList(start, start + 50).stream()
                    .map(entry -> new AuthenticatorEntryRepository.Mutation(entry.getId(), entry)).toList();
            assertThat(entries.applyBatch(user, chunk).error()).isNull();
        }
        Map<UUID, UUID> previous = new HashMap<>();
        Map<UUID, EntryService.PutEntryRequest> rotated = new HashMap<>();
        for (AuthenticatorEntry entry : stored) {
            previous.put(entry.getId(), entry.getMutationId());
            rotated.put(entry.getId(), largestRequest(2));
        }

        // Another device changes the passphrase after this client prepared the rotation.
        locks.saveChecked(subject, new LockSettings(300, false, key(1, 9)), revision);
        assertThatThrownBy(() -> rotation.rotate(user, previous, rotated, key(2, 10), 300, false, revision))
                .isInstanceOf(VaultChangedException.class);

        // Prepared against the current revision, all 1,000 accounts (at the largest accepted sizes) rotate in one transaction.
        long current = FirestoreLockSettingsRepository.revision(userDocument(user));
        VaultRotationService.Result result = rotation.rotate(user, previous, rotated, key(2, 10), 300, false, current);
        assertThat(result.entries()).hasSize(EntryService.MAX_ENTRIES_PER_USER);
        assertThat(result.lock().vaultRevision()).isEqualTo(current + 1);
        assertThat(entries.findAllByGoogleSubject(subject)).allMatch(entry -> entry.getKeyVersion() == 2);
        assertThat(userDocument(user).getLong("entryCount")).isEqualTo((long) EntryService.MAX_ENTRIES_PER_USER);

        // An account added afterwards with the old key version is refused with a code the client drops.
        AuthenticatorEntryRepository.BatchResult stale = entries.applyBatch(user,
                List.of(new AuthenticatorEntryRepository.Mutation(UUID.randomUUID(), entry(user, UUID.randomUUID(), 1))));
        assertThat(stale.errorCode()).isEqualTo("STALE_KEY");
    }

    @Test
    void rotationChecksRevisionBeforeCollectionReadsAndChargesTheStoredCount() throws Exception {
        var user = user();
        long revision = locks.saveChecked(user.googleSubject(),new LockSettings(300,false,key(1,1)),null);
        for(int i=0;i<3;i++) {
            var entry=entry(user,UUID.randomUUID(),1);
            entries.save(entry,user);
        }
        var charged=new java.util.concurrent.atomic.AtomicInteger();
        assertThatThrownBy(()->rotation.rotate(user,Map.of(),Map.of(),key(2,2),300,false,revision-1,charged::set))
                .isInstanceOf(VaultChangedException.class);
        assertThat(charged.get()).isZero();
        // An empty submitted list still pays for reading the existing collection before it is rejected.
        assertThatThrownBy(()->rotation.rotate(user,Map.of(),Map.of(),key(2,2),300,false,revision,charged::set))
                .isInstanceOf(VaultChangedException.class);
        assertThat(charged.get()).isEqualTo(3);
        assertThat(entries.findAllByGoogleSubject(user.googleSubject())).hasSize(3);
    }

    @Test
    void replacingAWrappedKeyNeedsARecentGoogleSignIn() throws Exception {
        String subject = user().googleSubject();
        long first = locks.saveChecked(subject, new LockSettings(300, false, key(1, 1)), null, false); // first key: allowed
        assertThatThrownBy(() -> locks.saveChecked(subject, new LockSettings(300, false, key(1, 2)), first, false))
                .isInstanceOf(dev.authsync.config.ReauthenticationRequiredException.class);
        assertThat(locks.saveChecked(subject, new LockSettings(600, false, key(1, 1)), first, false)).isEqualTo(first); // timeout only
        assertThat(locks.saveChecked(subject, new LockSettings(300, false, key(1, 2)), first, true)).isEqualTo(first + 1);
    }

    @Test
    void afterAResetNoSaveRecreatesTheVaultUntilANewPassphraseIsSet() throws Exception {
        AuthenticatedUser user = user();
        String subject = user.googleSubject();
        locks.saveChecked(subject, new LockSettings(300, false, key(1, 1)), null);
        save(user, entry(user, UUID.randomUUID(), 1));
        VaultResetService resets = new VaultResetService(firestore,
                new ClientSessionService(new FirestoreClientSessionRepository(firestore), new AuthSyncProperties("web", "extension", "")),
                Clock.systemUTC());

        resets.reset(subject);

        DocumentSnapshot afterReset = userDocument(user);
        assertThat(afterReset.getString("vaultResetStatus")).isEqualTo("COMPLETE");
        assertThatCode(() -> resets.beforeSignIn(subject)).doesNotThrowAnyException();
        assertThat(FirestoreLockSettingsRepository.accountExists(afterReset)).isFalse();
        assertThat(entries.findAllByGoogleSubject(subject)).isEmpty();
        // A save that was still in flight during the reset is refused instead of re-creating data.
        AuthenticatorEntryRepository.BatchResult late = entries.applyBatch(user,
                List.of(new AuthenticatorEntryRepository.Mutation(UUID.randomUUID(), entry(user, UUID.randomUUID(), 1))));
        assertThat(late.errorCode()).isEqualTo("VAULT_RESET");
        assertThat(entries.findAllByGoogleSubject(subject)).isEmpty();
        // Setting up a new passphrase starts a fresh vault.
        locks.saveChecked(subject, new LockSettings(300, false, key(1, 2)), FirestoreLockSettingsRepository.revision(afterReset));
        AuthenticatedUser fresh = new AuthenticatedUser(subject, user.email(), user.displayName(), FirestoreLockSettingsRepository.generation(afterReset));
        assertThat(entries.applyBatch(fresh, List.of(new AuthenticatorEntryRepository.Mutation(UUID.randomUUID(),
                entry(user, UUID.randomUUID(), 1)))).error()).isNull();
    }

    @Test
    void authenticatedWritesFromBeforeResetCannotEnterTheNewVault() throws Exception {
        AuthenticatedUser old = user();
        String subject = old.googleSubject();
        locks.saveChecked(subject, new LockSettings(300, false, key(1, 1)), null);
        var delayed = entry(old, UUID.randomUUID(), 1);
        var sessionService = new ClientSessionService(new FirestoreClientSessionRepository(firestore), new AuthSyncProperties("web", "extension", ""));
        var resets = new VaultResetService(firestore, sessionService, Clock.systemUTC());
        resets.reset(subject, 0L);
        var marker = userDocument(old);
        locks.saveChecked(subject, new LockSettings(300, false, key(1, 2)), FirestoreLockSettingsRepository.revision(marker));
        var late = entries.applyBatch(old, List.of(new AuthenticatorEntryRepository.Mutation(delayed.getId(), delayed)));
        assertThat(late.errorCode()).isEqualTo("VAULT_RESET");
        var fresh = new AuthenticatedUser(subject, old.email(), old.displayName(), 1);
        save(fresh, entry(fresh, UUID.randomUUID(), 1));
        assertThatThrownBy(() -> entries.deleteByIdAndUser(entries.findAllByGoogleSubject(subject).getFirst().getId(), old))
                .isInstanceOf(dev.authsync.entry.RejectedChangeException.class);
        assertThatThrownBy(() -> resets.reset(subject, 0L)).isInstanceOf(VaultChangedException.class);
        long currentRevision = FirestoreLockSettingsRepository.revision(userDocument(old));
        assertThatThrownBy(() -> locks.saveChecked(subject, new LockSettings(600, false, key(1, 2)), currentRevision, true, 0L))
                .isInstanceOf(VaultChangedException.class);
        assertThat(entries.findAllByGoogleSubject(subject)).hasSize(1);
    }

    @Test
    void expiredResetStillBlocksSetupAndSessionCreationUntilCleanupCompletes() throws Exception {
        AuthenticatedUser user = user();
        var reference = firestore.collection("users").document(user.googleSubject());
        reference.set(Map.of("vaultRevision", 2L, "vaultGeneration", 1L, "vaultResetStatus", "IN_PROGRESS",
                "vaultResetLease", "paused", "vaultResetAt", com.google.cloud.Timestamp.ofTimeSecondsAndNanos(1, 0))).get();
        assertThatThrownBy(() -> locks.saveChecked(user.googleSubject(), new LockSettings(300, false, key(1, 1)), 2L, true))
                .isInstanceOf(VaultResettingException.class);
        var repository = new FirestoreClientSessionRepository(firestore);
        var stored = new dev.authsync.session.ClientSessionRepository.StoredSession("hash", "", "", Instant.now().plusSeconds(3600));
        assertThatThrownBy(() -> repository.replaceChecked(user.googleSubject(), dev.authsync.session.ClientType.WEB, stored))
                .isInstanceOf(VaultResettingException.class);
        new VaultResetService(firestore, new ClientSessionService(repository, new AuthSyncProperties("web", "extension", "")), Clock.systemUTC())
                .beforeSignIn(user.googleSubject());
        var accepted = repository.replaceChecked(user.googleSubject(), dev.authsync.session.ClientType.WEB, stored);
        assertThat(accepted.vaultGeneration()).isEqualTo(1);
        assertThat(repository.find(user.googleSubject(), dev.authsync.session.ClientType.WEB).orElseThrow().vaultGeneration()).isEqualTo(1);
    }

    @Test
    void sessionRegistrationCannotSlipPastAResetThatStartedAfterTheSignInGate() throws Exception {
        AuthenticatedUser user = user();
        var repository = new FirestoreClientSessionRepository(firestore);
        var sessions = new ClientSessionService(repository, new AuthSyncProperties("web", "extension", ""));
        var resets = new VaultResetService(firestore, sessions, Clock.systemUTC());
        resets.beforeSignIn(user.googleSubject());
        firestore.collection("users").document(user.googleSubject()).set(Map.of("vaultResetStatus", "IN_PROGRESS", "vaultResetAt", com.google.cloud.Timestamp.now())).get();
        assertThatThrownBy(() -> repository.replaceChecked(user.googleSubject(), dev.authsync.session.ClientType.WEB,
                new dev.authsync.session.ClientSessionRepository.StoredSession("hash", "", "", Instant.now().plusSeconds(3600))))
                .isInstanceOf(VaultResettingException.class);
        assertThat(repository.find(user.googleSubject(), dev.authsync.session.ClientType.WEB)).isEmpty();
    }

    @Test
    void anEditMadeFromAnOlderVersionIsRefusedInsteadOfOverwritingTheNewerOne() {
        AuthenticatedUser user = user();
        UUID id = UUID.randomUUID();
        AuthenticatorEntry original = entry(user, id, 1);
        save(user, original);
        AuthenticatorEntry newer = entry(user, id, 1);
        assertThat(entries.applyBatch(user, List.of(new AuthenticatorEntryRepository.Mutation(id, newer, original.getMutationId()))).error()).isNull();

        // A delayed upload of another edit, also made from the original version, arrives late.
        AuthenticatorEntryRepository.BatchResult late = entries.applyBatch(user,
                List.of(new AuthenticatorEntryRepository.Mutation(id, entry(user, id, 1), original.getMutationId())));

        assertThat(late.errorCode()).isEqualTo("CONFLICT");
        assertThat(entries.findAllByGoogleSubject(user.googleSubject()))
                .extracting(AuthenticatorEntry::getMutationId).containsExactly(newer.getMutationId());
        // A retry of the change that was applied is still accepted (idempotent).
        assertThat(entries.applyBatch(user, List.of(new AuthenticatorEntryRepository.Mutation(id, newer, original.getMutationId()))).error()).isNull();
    }

    @Test
    void anEditOfADeletedEntryDoesNotRecreateIt() {
        AuthenticatedUser user = user();
        UUID id = UUID.randomUUID();
        AuthenticatorEntry original = entry(user, id, 1);
        save(user, original);
        entries.deleteByIdAndGoogleSubject(id, user.googleSubject());

        AuthenticatorEntryRepository.BatchResult offlineEdit = entries.applyBatch(user,
                List.of(new AuthenticatorEntryRepository.Mutation(id, entry(user, id, 1), original.getMutationId())));

        assertThat(offlineEdit.errorCode()).isEqualTo("DELETED");
        assertThat(entries.findAllByGoogleSubject(user.googleSubject())).isEmpty();
    }

    @Test
    void withRequireEditBaseAnUpdateWithoutItsBaseVersionIsRefused() {
        FirestoreAuthenticatorEntryRepository strict = new FirestoreAuthenticatorEntryRepository(firestore, new AuthSyncProperties("web", "extension", ""));
        AuthenticatedUser user = user();
        UUID id = UUID.randomUUID();
        AuthenticatorEntry original = entry(user, id, 1);
        assertThat(strict.applyBatch(user, List.of(new AuthenticatorEntryRepository.Mutation(id, original))).error()).isNull(); // a new entry

        AuthenticatorEntryRepository.BatchResult outdated = strict.applyBatch(user, List.of(new AuthenticatorEntryRepository.Mutation(id, entry(user, id, 1))));

        assertThat(outdated.errorCode()).isEqualTo("STALE_KEY");
        assertThat(strict.findAllByGoogleSubject(user.googleSubject()))
                .extracting(AuthenticatorEntry::getMutationId).containsExactly(original.getMutationId());
        // A retry of the change that was applied, and an edit naming its base, are accepted.
        assertThat(strict.applyBatch(user, List.of(new AuthenticatorEntryRepository.Mutation(id, original))).error()).isNull();
        assertThat(strict.applyBatch(user, List.of(new AuthenticatorEntryRepository.Mutation(id, entry(user, id, 1), original.getMutationId()))).error()).isNull();
    }

    private static AuthenticatedUser user() {
        return new AuthenticatedUser("emulator-" + UUID.randomUUID(), "user@example.com", "Emulator User");
    }

    @Test
    void anOriginalCreateRetryCannotResurrectADeletedAccount() throws Exception {
        AuthenticatedUser user = user();
        AuthenticatorEntry original = entry(user, UUID.randomUUID(), 1);
        save(user, original);
        entries.deleteByIdAndGoogleSubject(original.getId(), user.googleSubject());
        var replay = entries.applyBatch(user, List.of(new AuthenticatorEntryRepository.Mutation(original.getId(), original)));
        assertThat(replay.errorCode()).isEqualTo("DELETED");
        assertThat(entries.findAllByGoogleSubject(user.googleSubject())).isEmpty();
        var marker = firestore.collection("users").document(user.googleSubject()).collection("deletedEntries")
                .document(original.getId().toString()).get().get();
        assertThat(marker.exists()).isTrue();
        assertThat(marker.contains("expireAt")).isFalse();
        // Re-adding the same authenticator with a fresh ID remains possible.
        save(user, entry(user, UUID.randomUUID(), 1));
        assertThat(userDocument(user).getLong("entryCount")).isEqualTo(1L);
    }

    @Test
    void aDeleteEarlierInTheSameBatchAlsoReservesTheId() {
        AuthenticatedUser user = user();
        AuthenticatorEntry original = entry(user, UUID.randomUUID(), 1);
        save(user, original);
        var result = entries.applyBatch(user, List.of(
                new AuthenticatorEntryRepository.Mutation(original.getId(), null),
                new AuthenticatorEntryRepository.Mutation(original.getId(), original)));
        assertThat(result.applied()).isEqualTo(1);
        assertThat(result.errorCode()).isEqualTo("DELETED");
        assertThat(entries.findAllByGoogleSubject(user.googleSubject())).isEmpty();
    }

    @Test
    void oldCleanupBatchesCannotDeleteAfterLeaseTakeoverOrNewVaultSetup() throws Exception {
        AuthenticatedUser user = user();
        var reference = firestore.collection("users").document(user.googleSubject());
        var account = reference.collection("entries").document(UUID.randomUUID().toString());
        account.set(Map.of("fresh", true)).get();
        reference.set(Map.of("vaultResetStatus", "IN_PROGRESS", "vaultResetLease", "new-worker",
                "vaultResetAt", com.google.cloud.Timestamp.now())).get();
        var resets = new VaultResetService(firestore,
                new ClientSessionService(new FirestoreClientSessionRepository(firestore), new AuthSyncProperties("web", "extension", "")), Clock.systemUTC());
        assertThat(resets.deleteBatch(user.googleSubject(), "old-worker", List.of(account))).isFalse();
        assertThat(account.get().get().exists()).isTrue();
        assertThatThrownBy(() -> resets.beforeSignIn(user.googleSubject())).isInstanceOf(VaultResettingException.class);
        reference.update("vaultResetStatus", "COMPLETE").get();
        assertThat(resets.deleteBatch(user.googleSubject(), "new-worker", List.of(account))).isFalse();
        assertThat(account.get().get().exists()).isTrue();
    }

    @Test
    void expiredResetIsRecovered() throws Exception {
        AuthenticatedUser user = user();
        var reference = firestore.collection("users").document(user.googleSubject());
        var account = reference.collection("entries").document(UUID.randomUUID().toString());
        account.set(Map.of("old", true)).get();
        reference.set(Map.of("vaultResetStatus", "IN_PROGRESS", "vaultResetLease", "worker",
                "vaultResetAt", com.google.cloud.Timestamp.ofTimeSecondsAndNanos(1, 0))).get();
        var resets = new VaultResetService(firestore,
                new ClientSessionService(new FirestoreClientSessionRepository(firestore), new AuthSyncProperties("web", "extension", "")), Clock.systemUTC());
        resets.beforeSignIn(user.googleSubject());
        assertThat(account.get().get().exists()).isFalse();
        assertThat(userDocument(user).getString("vaultResetStatus")).isEqualTo("COMPLETE");
        assertThat(resets.deleteBatch(user.googleSubject(), "worker", List.of(account))).isFalse();
    }

    @Test
    void resetCleansMultipleBatchesAndNestedData() throws Exception {
        AuthenticatedUser user = user();
        var reference = firestore.collection("users").document(user.googleSubject());
        var batch=firestore.batch();
        for(int i=0;i<205;i++) batch.set(reference.collection("authenticatorEntries").document("entry-"+i),Map.of("test",true));
        var nested=reference.collection("authenticatorEntries").document("entry-0").collection("oldSchema").document("secret");
        var orphan=reference.collection("authenticatorEntries").document("missing-parent").collection("oldSchema").document("secret");
        batch.set(nested,Map.of("test",true));
        batch.set(orphan,Map.of("test",true));
        batch.commit().get();
        var resets = new VaultResetService(firestore,
                new ClientSessionService(new FirestoreClientSessionRepository(firestore), new AuthSyncProperties("web", "extension", "")), Clock.systemUTC());
        resets.reset(user.googleSubject());
        assertThat(reference.collection("authenticatorEntries").get().get().isEmpty()).isTrue();
        assertThat(nested.get().get().exists()).isFalse();
        assertThat(orphan.get().get().exists()).isFalse();
        assertThat(userDocument(user).getString("vaultResetStatus")).isEqualTo("COMPLETE");
    }

    @Test
    void deltaUsesDatabaseTimeWhenApiClockIsWrong() {
        var user = user();
        var skewed = new EntryService(entries, Clock.fixed(Instant.parse("2099-01-01T00:00:00Z"), java.time.ZoneOffset.UTC));
        var before = skewed.changes(user.googleSubject(), null);
        var slow = new EntryService(entries, Clock.fixed(Instant.parse("2000-01-01T00:00:00Z"), java.time.ZoneOffset.UTC));
        var id = UUID.randomUUID();
        slow.put(user, id, request(1));
        var delta = skewed.changes(user.googleSubject(), before.cursor());
        assertThat(delta.entries()).extracting(EntryService.EntryResponse::id).contains(id);
    }

    private static void save(AuthenticatedUser user, AuthenticatorEntry entry) {
        assertThat(entries.applyBatch(user, List.of(new AuthenticatorEntryRepository.Mutation(entry.getId(), entry))).error()).isNull();
    }

    private static DocumentSnapshot userDocument(AuthenticatedUser user) throws Exception {
        return firestore.collection("users").document(user.googleSubject()).get().get();
    }

    private static AuthenticatorEntry entry(AuthenticatedUser user, UUID id, int keyVersion) {
        Instant now = Instant.now();
        return new AuthenticatorEntry(id, user.googleSubject(), "Encrypted", "Encrypted", new byte[32], new byte[12], keyVersion,
                "SHA1", 6, 30, now, now, UUID.randomUUID());
    }

    // The largest entry the API accepts: 1 KiB secret ciphertext and 2 KiB encrypted label.
    private static AuthenticatorEntry largestEntry(AuthenticatedUser user, UUID id, int keyVersion) {
        Instant now = Instant.now();
        return new AuthenticatorEntry(id, user.googleSubject(), "Encrypted", "Encrypted", new byte[1024], new byte[12], keyVersion,
                "SHA1", 6, 30, now, now, UUID.randomUUID(), new byte[2048], new byte[12]);
    }

    private static EntryService.PutEntryRequest largestRequest(int keyVersion) {
        Base64.Encoder base64 = Base64.getEncoder();
        return new EntryService.PutEntryRequest("Encrypted", "Encrypted", base64.encodeToString(new byte[1024]),
                base64.encodeToString(new byte[12]), keyVersion, "SHA1", 6, 30, System.currentTimeMillis(), UUID.randomUUID(),
                base64.encodeToString(new byte[2048]), base64.encodeToString(new byte[12]));
    }

    private static EntryService.PutEntryRequest request(int keyVersion) {
        Base64.Encoder base64 = Base64.getEncoder();
        return new EntryService.PutEntryRequest("Encrypted", "Encrypted", base64.encodeToString(new byte[32]),
                base64.encodeToString(new byte[12]), keyVersion, "SHA1", 6, 30, System.currentTimeMillis(), UUID.randomUUID());
    }

    /** A structurally valid wrapped key; {@code variant} makes the wrapped bytes differ. */
    private static WrappedVaultKey key(int version, int variant) {
        Base64.Encoder base64 = Base64.getEncoder();
        byte[] wrapped = new byte[48];
        wrapped[0] = (byte) variant;
        return new WrappedVaultKey(version, 1, System.currentTimeMillis(), "PBKDF2-SHA256/AES-256-GCM", 600_000,
                base64.encodeToString(new byte[16]), base64.encodeToString(new byte[12]), base64.encodeToString(wrapped));
    }
}
