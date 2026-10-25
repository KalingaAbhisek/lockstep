package dev.authsync.config;

import java.time.Duration;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Waits for a Firestore call with a deadline. Firestore retries failed calls by itself; if the database is
 * unreachable or very slow, the request gives up after {@link #TIMEOUT} (and cancels the call) with a 503
 * instead of holding a server thread and a client connection open for minutes.
 */
public final class FirestoreCalls {
    /** The longest one Firestore call (including the client library's retries) may take for an API request. */
    public static final Duration TIMEOUT = Duration.ofSeconds(30);

    private FirestoreCalls() {}

    /** The database did not answer in time. Answered with 503 (see ApiExceptionHandler). */
    public static class DatabaseUnavailableException extends RuntimeException {
        public DatabaseUnavailableException(String message, Throwable cause) { super(message, cause); }
    }

    /**
     * The future's result. A {@link RuntimeException} thrown by the operation is passed on unchanged (for
     * example VaultChangedException from a transaction); other failures become IllegalStateException.
     */
    public static <T> T await(Future<T> future, String operation) {
        return await(future, operation, TIMEOUT);
    }

    public static <T> T await(Future<T> future, String operation, Duration timeout) {
        try {
            return future.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException exception) {
            future.cancel(true);
            throw new DatabaseUnavailableException(operation + " timed out", exception);
        } catch (InterruptedException exception) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new IllegalStateException(operation + " was interrupted", exception);
        } catch (ExecutionException exception) {
            Throwable cause=exception.getCause();
            boolean transientFailure=false;
            if(cause instanceof com.google.cloud.firestore.FirestoreException firestore) {
                transientFailure=firestore.isRetryable() || switch(firestore.getStatus().getCode()) {
                    case UNAVAILABLE,DEADLINE_EXCEEDED,RESOURCE_EXHAUSTED,ABORTED -> true;
                    default -> false;
                };
            } else if(cause instanceof com.google.api.gax.rpc.ApiException rpc) {
                transientFailure=rpc.isRetryable() || switch(rpc.getStatusCode().getCode()) {
                    case UNAVAILABLE,DEADLINE_EXCEEDED,RESOURCE_EXHAUSTED,ABORTED -> true;
                    default -> false;
                };
            }
            if(transientFailure)throw new DatabaseUnavailableException(operation+" is temporarily unavailable",cause);
            if (exception.getCause() instanceof RuntimeException runtime) throw runtime;
            throw new IllegalStateException(operation + " failed", exception.getCause());
        }
    }
}
