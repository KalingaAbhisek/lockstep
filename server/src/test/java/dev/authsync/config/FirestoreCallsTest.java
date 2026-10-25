package dev.authsync.config;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.CompletableFuture;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class FirestoreCallsTest {
    @Test
    void transientDatabaseRejectionsUseTheAvailabilityResponse() {
        for(var status:java.util.List.of(io.grpc.Status.UNAVAILABLE,io.grpc.Status.DEADLINE_EXCEEDED,io.grpc.Status.RESOURCE_EXHAUSTED,io.grpc.Status.ABORTED)) {
            var failure=com.google.cloud.firestore.FirestoreException.forServerRejection(status,"simulated outage");
            assertThatThrownBy(()->FirestoreCalls.await(CompletableFuture.failedFuture(failure),"Lookup"))
                .isInstanceOf(FirestoreCalls.DatabaseUnavailableException.class).hasCause(failure);
        }
        var invalid=com.google.cloud.firestore.FirestoreException.forInvalidArgument("invalid field");
        assertThatThrownBy(()->FirestoreCalls.await(CompletableFuture.failedFuture(invalid),"Lookup")).isSameAs(invalid);
    }

    @Test
    void interruptedWaitCancelsTheCallAndPreservesInterruptStatus() {
        var pending=new CompletableFuture<String>();
        try {
            Thread.currentThread().interrupt();
            assertThatThrownBy(()->FirestoreCalls.await(pending,"Lookup")).isInstanceOf(IllegalStateException.class);
            assertThat(pending.isCancelled()).isTrue();assertThat(Thread.currentThread().isInterrupted()).isTrue();
        }finally{Thread.interrupted();}
    }

    @Test
    void aCallThatNeverAnswersIsCancelledAfterTheDeadline() {
        CompletableFuture<String> neverAnswers = new CompletableFuture<>();
        assertThatThrownBy(() -> FirestoreCalls.await(neverAnswers, "Lookup", Duration.ofMillis(50)))
                .isInstanceOf(FirestoreCalls.DatabaseUnavailableException.class)
                .hasMessageContaining("Lookup timed out");
        assertThat(neverAnswers.isCancelled()).isTrue();
    }

    @Test
    void passesOnResultsAndTheOperationsOwnExceptions() {
        assertThat(FirestoreCalls.await(CompletableFuture.completedFuture("ok"), "Lookup")).isEqualTo("ok");
        IllegalArgumentException own = new IllegalArgumentException("conflict");
        assertThatThrownBy(() -> FirestoreCalls.await(CompletableFuture.failedFuture(own), "Lookup")).isSameAs(own);
        assertThatThrownBy(() -> FirestoreCalls.await(CompletableFuture.failedFuture(new java.io.IOException("io")), "Lookup"))
                .isInstanceOf(IllegalStateException.class).hasMessageContaining("Lookup failed");
    }
}
