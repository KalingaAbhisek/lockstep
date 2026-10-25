package dev.authsync.config;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.Map;

@RestControllerAdvice
public class ApiExceptionHandler {
    @ExceptionHandler(IllegalArgumentException.class)
    ResponseEntity<Map<String, String>> badRequest(IllegalArgumentException exception) {
        if (exception instanceof dev.authsync.entry.RejectedChangeException rejected) {
            return ResponseEntity.badRequest().body(Map.of("code", rejected.code(), "error", rejected.getMessage()));
        }
        return ResponseEntity.badRequest().body(Map.of("error", exception.getMessage()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ResponseEntity<Map<String, String>> validation(MethodArgumentNotValidException exception) {
        String message = exception.getBindingResult().getFieldErrors().stream()
                .findFirst().map(error -> error.getField() + ": " + error.getDefaultMessage())
                .orElse("Invalid request");
        return ResponseEntity.badRequest().body(Map.of("error", message));
    }

    @ExceptionHandler(ReauthenticationRequiredException.class)
    ResponseEntity<Map<String, String>> reauthenticate(ReauthenticationRequiredException exception) {
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(Map.of("code", "REAUTH_REQUIRED", "error", exception.getMessage()));
    }

    @ExceptionHandler(dev.authsync.vault.VaultResettingException.class)
    ResponseEntity<Map<String, String>> resetting(dev.authsync.vault.VaultResettingException exception) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("code", "VAULT_RESETTING", "error", exception.getMessage()));
    }

    // The database did not answer within FirestoreCalls.TIMEOUT: the apps keep their local copy and retry later.
    @ExceptionHandler(FirestoreCalls.DatabaseUnavailableException.class)
    ResponseEntity<Map<String, String>> databaseUnavailable(FirestoreCalls.DatabaseUnavailableException exception) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).header("Retry-After", "30")
                .body(Map.of("code", "BACKEND_UNAVAILABLE", "error", "Lockstep is temporarily unavailable. Please try again in a moment."));
    }

    @ExceptionHandler(dev.authsync.vault.VaultChangedException.class)
    ResponseEntity<Map<String, String>> vaultChanged(dev.authsync.vault.VaultChangedException exception) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of("code", "VAULT_CHANGED", "error", exception.getMessage()));
    }

    // A body that could not be read: 413 when it was cut off for being too large (chunked uploads without a
    // declared length), otherwise the same 400 as before.
    @ExceptionHandler(HttpMessageNotReadableException.class)
    ResponseEntity<Map<String, String>> unreadable(HttpMessageNotReadableException exception) {
        if (RequestBodyLimitFilter.causedByTooLarge(exception)) {
            return ResponseEntity.status(413).body(Map.of("code", "REQUEST_TOO_LARGE", "error", "The request is too large."));
        }
        return ResponseEntity.badRequest().body(Map.of("error", "The request body is invalid."));
    }

    @ExceptionHandler(OperationRateLimiter.RateLimitedException.class)
    ResponseEntity<Map<String, String>> rateLimited(OperationRateLimiter.RateLimitedException exception) {
        return ResponseEntity.status(HttpStatus.TOO_MANY_REQUESTS).header("Retry-After", "60")
                .body(Map.of("code", "RATE_LIMITED", "error", exception.getMessage()));
    }

    @ExceptionHandler(EntryNotFoundException.class)
    ResponseEntity<Map<String, String>> notFound(EntryNotFoundException exception) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", exception.getMessage()));
    }
}

