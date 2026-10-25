package dev.authsync.entry;

import jakarta.validation.Valid;
import jakarta.validation.Validator;
import jakarta.validation.constraints.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/entries")
public class EntryController {
    private static final int MAX_BATCH_OPERATIONS = 50;
    private final EntryService service;
    private final Validator validator;
    private final dev.authsync.config.OperationRateLimiter operationLimiter;
    private final dev.authsync.config.RecentSignInPolicy recentSignIn;

    public EntryController(EntryService service, Validator validator, dev.authsync.config.OperationRateLimiter operationLimiter,
                           dev.authsync.config.RecentSignInPolicy recentSignIn) {
        this.service = service;
        this.validator = validator;
        this.operationLimiter = operationLimiter;
        this.recentSignIn = recentSignIn;
    }

    @GetMapping
    List<EntryService.EntryResponse> list(@org.springframework.security.core.annotation.AuthenticationPrincipal Jwt jwt) {
        return service.list(jwt.getSubject());
    }

    /** Delta sync: see {@link EntryService#changes}. */
    @GetMapping("/changes")
    EntryService.Changes changes(@org.springframework.security.core.annotation.AuthenticationPrincipal Jwt jwt,
                                 @RequestParam(name = "since", required = false) Long since) {
        return service.changes(jwt.getSubject(), since);
    }

    @PutMapping("/{id}")
    EntryService.EntryResponse put(@org.springframework.security.core.annotation.AuthenticationPrincipal Jwt jwt,
                                   @PathVariable UUID id, @Valid @RequestBody PutEntryRequest request) {
        operationLimiter.require(jwt.getSubject(), 1);
        return service.put(authenticatedUser(jwt), id, request.toServiceRequest());
    }

    @DeleteMapping("/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void delete(@org.springframework.security.core.annotation.AuthenticationPrincipal Jwt jwt, @PathVariable UUID id) {
        recentSignIn.require(jwt);
        operationLimiter.require(jwt.getSubject(), 1);
        service.delete(authenticatedUser(jwt), id);
    }

    /**
     * Applies several queued client changes in one request and one database transaction. Each change is
     * validated like the matching PUT or DELETE endpoint; processing stops at the first rejected change
     * and the response says how many were applied so the client keeps the rest queued.
     */
    @PostMapping("/batch")
    BatchResponse batch(@org.springframework.security.core.annotation.AuthenticationPrincipal Jwt jwt,
                        @RequestBody BatchRequest request) {
        List<BatchOperation> operations = request == null || request.operations() == null ? List.of() : request.operations();
        if (operations.isEmpty() || operations.size() > MAX_BATCH_OPERATIONS) {
            throw new IllegalArgumentException("operations: must contain 1 to " + MAX_BATCH_OPERATIONS + " changes");
        }
        if (operations.stream().anyMatch(op -> op != null && "DELETE".equalsIgnoreCase(String.valueOf(op.operation()).trim()))) recentSignIn.require(jwt);
        operationLimiter.require(jwt.getSubject(), operations.size());
        List<EntryService.BatchChange> changes = new ArrayList<>();
        String rejection = null;
        for (BatchOperation operation : operations) {
            try {
                changes.add(toChange(operation));
            } catch (IllegalArgumentException exception) {
                rejection = exception.getMessage();
                break;
            }
        }
        EntryService.BatchOutcome outcome = service.applyBatch(authenticatedUser(jwt), changes);
        String error = outcome.error() != null ? outcome.error() : outcome.applied() == changes.size() ? rejection : null;
        String code = outcome.error() != null ? outcome.errorCode() : null;
        return new BatchResponse(outcome.applied(), error == null ? null : new BatchError(400, error, code));
    }

    private EntryService.BatchChange toChange(BatchOperation operation) {
        if (operation == null || operation.entryId() == null) throw new IllegalArgumentException("entryId: must not be null");
        String type = operation.operation() == null ? "" : operation.operation().trim().toUpperCase();
        switch (type) {
            case "PUT" -> {
                PutEntryRequest request = operation.payload();
                if (request == null) throw new IllegalArgumentException("payload: must not be null");
                // Same bean-validation rules (and message format) as the single PUT endpoint.
                String violation = validator.validate(request).stream().findFirst()
                        .map(error -> error.getPropertyPath() + ": " + error.getMessage()).orElse(null);
                if (violation != null) throw new IllegalArgumentException(violation);
                return new EntryService.BatchChange(operation.entryId(), false, request.toServiceRequest());
            }
            case "DELETE" -> { return new EntryService.BatchChange(operation.entryId(), true, null); }
            default -> throw new IllegalArgumentException("operation: must be PUT or DELETE");
        }
    }

    private static AuthenticatedUser authenticatedUser(Jwt jwt) {
        String verifiedEmail = Boolean.TRUE.equals(jwt.getClaim("email_verified")) ? jwt.getClaimAsString("email") : null;
        return new AuthenticatedUser(jwt.getSubject(), verifiedEmail, jwt.getClaimAsString("name"), AuthenticatedUser.generation(jwt));
    }

    public record PutEntryRequest(
            @NotBlank @Size(max = 128) String issuer,
            @NotBlank @Size(max = 256) String accountName,
            @NotBlank @Size(max = 1376) String encryptedSecret,
            @NotBlank @Size(max = 64) String secretIv,
            @Min(1) int keyVersion,
            @NotBlank @Size(max = 16) String algorithm,
            @Min(6) @Max(8) int digits,
            @Min(15) @Max(120) int periodSeconds,
            @Min(1) long createdAtEpochMillis,
            @NotNull UUID mutationId,
            @Size(max = 2752) String encryptedLabel,
            @Size(max = 64) String labelIv,
            // The stored mutation this edit was made from; null for a new entry (and from older clients).
            UUID baseMutationId) {
        public EntryService.PutEntryRequest toServiceRequest() {
            return new EntryService.PutEntryRequest(issuer, accountName, encryptedSecret, secretIv, keyVersion, algorithm,
                    digits, periodSeconds, createdAtEpochMillis, mutationId, encryptedLabel, labelIv, baseMutationId);
        }
    }

    public record BatchRequest(List<BatchOperation> operations) {}
    public record BatchOperation(String operation, UUID entryId, UUID mutationId, PutEntryRequest payload) {}
    public record BatchResponse(int applied, BatchError error) {}
    /** {@code code}: STALE_KEY, VAULT_RESET, CONFLICT or DELETED when the client should drop the refused change, otherwise null. */
    public record BatchError(int status, String message, String code) {}
}
