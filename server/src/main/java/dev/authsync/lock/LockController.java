package dev.authsync.lock;

import dev.authsync.config.RecentSignInPolicy;
import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/lock")
public class LockController {
    private final LockService service;
    private final RecentSignInPolicy recentSignIn;
    public LockController(LockService service, RecentSignInPolicy recentSignIn) {
        this.service = service;
        this.recentSignIn = recentSignIn;
    }

    @GetMapping
    LockService.LockConfig config(@AuthenticationPrincipal Jwt jwt) { return service.config(jwt.getSubject()); }

    @PutMapping
    LockService.LockConfig configure(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody ConfigureLockRequest request) {
        return service.configure(jwt.getSubject(), request.timeoutSeconds(), request.lockOnScreenLock(), request.wrappedKey(),
                request.expectedRevision(), recentSignIn.isRecent(jwt), dev.authsync.entry.AuthenticatedUser.generation(jwt));
    }

    // There is no DELETE: the passphrase cannot be removed, because it encrypts the vault key (no app offers
    // it, and deleting the wrapped key would stop new devices from opening the vault with the passphrase).

    // The passkey is intentionally not part of this request: it never leaves the user's device.
    // A "passcode" field sent by older clients is ignored. expectedRevision: the vault revision the client
    // last saw (newer clients); a different stored revision means another device changed the key (409).
    public record ConfigureLockRequest(@Min(300) @Max(604800) int timeoutSeconds,
                                       boolean lockOnScreenLock, WrappedVaultKey wrappedKey, Long expectedRevision) {}
}
