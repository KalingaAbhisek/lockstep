package dev.authsync.vault;

import dev.authsync.config.RecentSignInPolicy;
import dev.authsync.entry.AuthenticatedUser;
import dev.authsync.entry.EntryController;
import dev.authsync.entry.EntryService;
import dev.authsync.lock.WrappedVaultKey;
import jakarta.validation.Validator;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/vault")
public class VaultController {
    private final VaultResetService resets;
    private final VaultRotationService rotation;
    private final Validator validator;
    private final RecentSignInPolicy recentSignIn;
    private final dev.authsync.config.OperationRateLimiter operationLimiter;

    public VaultController(VaultResetService resets, VaultRotationService rotation, Validator validator, RecentSignInPolicy recentSignIn,
                           dev.authsync.config.OperationRateLimiter operationLimiter) {
        this.resets = resets;
        this.rotation = rotation;
        this.validator = validator;
        this.recentSignIn = recentSignIn;
        this.operationLimiter = operationLimiter;
    }

    /**
     * Atomic recovery-key rotation: the new wrapped key and all re-encrypted entries replace the old ones
     * together. {@code previous} lists every entry's mutation ID as the client last saw it; the rotation is
     * refused (409) if the server's vault differs, so concurrent changes are never overwritten.
     */
    @PostMapping("/rotate")
    VaultRotationService.Result rotate(@AuthenticationPrincipal Jwt jwt, @RequestBody RotateRequest request) {
        recentSignIn.require(jwt);
        if (request == null) throw new IllegalArgumentException("A rotation request is required");
        Map<UUID, UUID> previous = new HashMap<>();
        for (PreviousEntry entry : request.previous() == null ? List.<PreviousEntry>of() : request.previous()) {
            if (entry == null || entry.id() == null || entry.mutationId() == null) throw new IllegalArgumentException("previous: entries need an id and mutationId");
            if (previous.put(entry.id(), entry.mutationId()) != null) throw new IllegalArgumentException("previous: duplicate entry " + entry.id());
        }
        Map<UUID, EntryService.PutEntryRequest> entries = new HashMap<>();
        for (RotatedEntry entry : request.entries() == null ? List.<RotatedEntry>of() : request.entries()) {
            if (entry == null || entry.id() == null || entry.entry() == null) throw new IllegalArgumentException("entries: each entry needs an id and its data");
            String violation = validator.validate(entry.entry()).stream().findFirst()
                    .map(error -> error.getPropertyPath() + ": " + error.getMessage()).orElse(null);
            if (violation != null) throw new IllegalArgumentException(violation);
            if (entries.put(entry.id(), entry.entry().toServiceRequest()) != null) throw new IllegalArgumentException("entries: duplicate entry " + entry.id());
        }
        String verifiedEmail = Boolean.TRUE.equals(jwt.getClaim("email_verified")) ? jwt.getClaimAsString("email") : null;
        AuthenticatedUser user = new AuthenticatedUser(jwt.getSubject(), verifiedEmail, jwt.getClaimAsString("name"), AuthenticatedUser.generation(jwt));
        var permit = operationLimiter.reserveRotation(jwt.getSubject(), entries.size());
        return rotation.rotate(user, previous, entries, request.wrappedKey(), request.timeoutSeconds(), request.lockOnScreenLock(),
                request.expectedRevision(), permit::chargeRead);
    }

    /** {@code expectedRevision}: the vault revision the client prepared against (optional for older clients). */
    public record RotateRequest(int timeoutSeconds, boolean lockOnScreenLock, WrappedVaultKey wrappedKey,
                                List<RotatedEntry> entries, List<PreviousEntry> previous, Long expectedRevision) {}
    public record RotatedEntry(UUID id, EntryController.PutEntryRequest entry) {}
    public record PreviousEntry(UUID id, UUID mutationId) {}

    /** Deletes the whole vault (see VaultResetService). Needs a recent Google sign-in. */
    @DeleteMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void reset(@AuthenticationPrincipal Jwt jwt) {
        recentSignIn.require(jwt);
        resets.reset(jwt.getSubject(), AuthenticatedUser.generation(jwt));
    }
}
