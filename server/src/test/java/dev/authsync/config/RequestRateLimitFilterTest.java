package dev.authsync.config;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RequestRateLimitFilterTest {
    @Test
    void allowsUpToTheLimitPerKeyThenRefuses() {
        RequestRateLimitFilter filter = new RequestRateLimitFilter();
        for (int request = 0; request < 3; request++) assertThat(filter.tryAcquire("write\nuser-a", 3)).isTrue();
        assertThat(filter.tryAcquire("write\nuser-a", 3)).isFalse();
        assertThat(filter.tryAcquire("write\nuser-b", 3)).isTrue();
    }
}
