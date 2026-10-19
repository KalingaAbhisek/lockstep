package dev.authsync.entry;

import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/entries")
public class EntryController {
    private final EntryService service;

    public EntryController(EntryService service) { this.service = service; }

    @GetMapping
    List<EntryService.EntryResponse> list(@org.springframework.security.core.annotation.AuthenticationPrincipal Jwt jwt) {
        return service.list(jwt.getSubject());
    }

    @PutMapping("/{id}")
    EntryService.EntryResponse put(@org.springframework.security.core.annotation.AuthenticationPrincipal Jwt jwt,
                                   @PathVariable UUID id, @Valid @RequestBody PutEntryRequest request) {
        return service.put(authenticatedUser(jwt), id, new EntryService.PutEntryRequest(
                request.issuer(), request.accountName(), request.encryptedSecret(), request.secretIv(),
                request.keyVersion(), request.algorithm(), request.digits(), request.periodSeconds(),
                request.createdAtEpochMillis(), request.mutationId()));
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void delete(@org.springframework.security.core.annotation.AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        service.delete(jwt.getSubject(), id);
    }

    private static AuthenticatedUser authenticatedUser(Jwt jwt) {
        String verifiedEmail = Boolean.TRUE.equals(jwt.getClaim("email_verified")) ? jwt.getClaimAsString("email") : null;
        return new AuthenticatedUser(jwt.getSubject(), verifiedEmail, jwt.getClaimAsString("name"));
    }

    public record PutEntryRequest(
            @NotBlank @Size(max = 128) String issuer,
            @NotBlank @Size(max = 256) String accountName,
            @NotBlank @Size(max = 8192) String encryptedSecret,
            @NotBlank @Size(max = 64) String secretIv,
            @Min(1) int keyVersion,
            @NotBlank @Size(max = 16) String algorithm,
            @Min(6) @Max(8) int digits,
            @Min(15) @Max(120) int periodSeconds,
            @Min(1) long createdAtEpochMillis,
            @NotNull UUID mutationId) {}
}
