package dev.authsync.lock;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/lock")
public class LockController {
    private final LockService service;
    public LockController(LockService service) { this.service = service; }

    @GetMapping
    LockService.LockConfig config(@AuthenticationPrincipal Jwt jwt) { return service.config(jwt.getSubject()); }

    @PutMapping
    LockService.LockConfig configure(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody ConfigureLockRequest request) {
        return service.configure(jwt.getSubject(), request.passcode(), request.timeoutSeconds(), request.lockOnScreenLock(), request.wrappedKey());
    }

    @PostMapping("/verify")
    VerifyLockResponse verify(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody VerifyLockRequest request) {
        return new VerifyLockResponse(service.verify(jwt.getSubject(), request.passcode()));
    }

    @DeleteMapping
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void remove(@AuthenticationPrincipal Jwt jwt) { service.remove(jwt.getSubject()); }

    public record ConfigureLockRequest(@NotBlank @Size(min=4,max=128) String passcode,
                                       @Min(300) @Max(604800) int timeoutSeconds,
                                       boolean lockOnScreenLock, WrappedVaultKey wrappedKey) {}
    public record VerifyLockRequest(@NotBlank @Size(max=128) String passcode) {}
    public record VerifyLockResponse(boolean unlocked) {}
}
