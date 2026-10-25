package dev.authsync.bootstrap;

import dev.authsync.config.AuthSyncProperties;
import dev.authsync.entry.EntryService;
import dev.authsync.lock.LockService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.UUID;

/**
 * Everything a client needs when it opens, in one request: whether the account exists, the lock
 * settings and the encrypted entries. Returns exactly what GET /api/v1/account, GET /api/v1/lock and
 * GET /api/v1/entries return, with revision checks so clients receive a consistent key/ciphertext version.
 */
@RestController
@RequestMapping("/api/v1/bootstrap")
public class BootstrapController {
    private final LockService lockService;
    private final EntryService entryService;
    private final List<String> features;

    public BootstrapController(LockService lockService, EntryService entryService, AuthSyncProperties properties) {
        this.lockService = lockService;
        this.entryService = entryService;
        this.features = features(properties);
    }

    /**
     * With {@code since} (the cursor a client saved from its last sync) only the entries changed and the IDs
     * deleted after it are returned ({@code full} false), so reopening the app downloads only what changed.
     */
    @GetMapping
    Bootstrap bootstrap(@AuthenticationPrincipal Jwt jwt, @RequestParam(name = "since", required = false) Long since) {
        String subject = jwt.getSubject();
        // Rotation/reset increments the revision atomically with its key/ciphertext changes. Fence the
        // entry reads on both sides so a response cannot mix two vault versions.
        for (int attempt = 0; attempt < 3; attempt++) {
            LockService.AccountState state = lockService.accountState(subject);
            EntryService.Changes changes = entryService.changes(subject, since);
            LockService.AccountState after = lockService.accountState(subject);
            if (state.equals(after)) {
                return new Bootstrap(state.exists(), state.lock(), changes.entries(), changes.cursor(), features,
                        changes.deletedIds(), changes.full());
            }
        }
        throw new dev.authsync.vault.VaultChangedException("Your vault changed during startup. Try again.");
    }

    /**
     * {@code cursor} lets the client ask for changes since this point next time. {@code full}: entries is the
     * complete list (otherwise only changes, with {@code deletedIds}).
     */
    public record Bootstrap(boolean exists, LockService.LockConfig lock, List<EntryService.EntryResponse> entries, long cursor,
                            List<String> features, List<UUID> deletedIds, boolean full) {}

    /** What this server supports; clients only use these once the server says so. */
    static final List<String> FEATURES = List.of("encryptedLabels", "atomicRotation", "sessionCookie", "serverSignOut",
            "vaultRevision", "deltaBootstrap", "recentSignIn", "liveChanges");

    /** "argon2idWrapping" is announced while ARGON2ID_WRAPPING is on (the default); setting it to false returns clients to PBKDF2 for new keys. */
    static List<String> features(AuthSyncProperties properties) {
        if (!properties.argon2idWrapping()) return FEATURES;
        List<String> features = new java.util.ArrayList<>(FEATURES);
        features.add("argon2idWrapping");
        return List.copyOf(features);
    }
}
