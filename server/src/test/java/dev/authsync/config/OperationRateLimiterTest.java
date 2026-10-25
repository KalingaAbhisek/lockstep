package dev.authsync.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class OperationRateLimiterTest {
    @Test
    void consecutiveRotationsHaveNoCooldown() {
        var limiter = new OperationRateLimiter();
        // A second device and repeated retries can reserve immediately.
        for (int attempt = 0; attempt < 10; attempt++) {
            var permit = limiter.reserveRotation("shared-account", 10);
            permit.chargeRead(10);
        }
        assertThat(limiter.tryAcquire("shared-account", 1100)).isTrue();
        assertThat(limiter.tryAcquire("shared-account", 1)).isFalse();
    }

    @Test
    void rotationsChargeActualWorkWithoutChargingTransactionRetriesTwice() {
        var limiter = new OperationRateLimiter();
        var permit = limiter.reserveRotation("large", 0);
        permit.chargeRead(1000);
        permit.chargeRead(1000);
        assertThat(limiter.tryAcquire("large", 199)).isTrue();
        var next = limiter.reserveRotation("large", 0);
        assertThatThrownBy(() -> next.chargeRead(1000)).isInstanceOf(OperationRateLimiter.RateLimitedException.class);
        for (int attempt = 0; attempt < 10; attempt++) limiter.reserveRotation("invalid", 0);
    }

    @Test
    void aBatchCountsEachOfItsChanges() {
        OperationRateLimiter limiter = new OperationRateLimiter();
        for (int batch = 0; batch < OperationRateLimiter.MAX_OPERATIONS_PER_MINUTE / 50; batch++) limiter.require("user", 50);

        assertThatThrownBy(() -> limiter.require("user", 1)).isInstanceOf(OperationRateLimiter.RateLimitedException.class);
        assertThat(limiter.tryAcquire("someone-else", 50)).isTrue();
    }

    @Test
    void aRefusedBatchReservesNothing() {
        OperationRateLimiter limiter = new OperationRateLimiter();
        limiter.require("user", OperationRateLimiter.MAX_OPERATIONS_PER_MINUTE - 10);

        assertThat(limiter.tryAcquire("user", 50)).isFalse();
        assertThat(limiter.tryAcquire("user", 10)).isTrue();
    }
}
