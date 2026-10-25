package dev.authsync.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;

class RequestLimitsTest {
    @Test
    void readsAreRateLimitedTooButPreflightsAreNot() {
        RequestRateLimitFilter filter = new RequestRateLimitFilter();
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("GET", "/api/v1/bootstrap"))).isFalse();
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("PUT", "/api/v1/lock"))).isFalse();
        // HEAD runs the GET handler (and its database reads), so it is counted too.
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("HEAD", "/api/v1/bootstrap"))).isFalse();
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("OPTIONS", "/api/v1/bootstrap"))).isTrue();
        assertThat(filter.shouldNotFilter(new MockHttpServletRequest("GET", "/actuator/health"))).isTrue();
    }

    @Test
    void manyKeysDoNotResetOtherAccountsCounters() {
        RequestRateLimitFilter filter = new RequestRateLimitFilter();
        for (int request = 0; request < 3; request++) assertThat(filter.tryAcquire("write\nvictim", 3)).isTrue();
        for (int key = 0; key < 25_000; key++) filter.tryAcquire("write\nattacker-" + key, 3);
        assertThat(filter.tryAcquire("write\nvictim", 3)).isFalse();
    }

    @Test
    void onlyKeyRotationMayUploadUpToSixMebibytes() {
        assertThat(RequestBodyLimitFilter.limitFor(new MockHttpServletRequest("POST", "/api/v1/vault/rotate")))
                .isEqualTo(6L * 1024 * 1024);
        assertThat(RequestBodyLimitFilter.limitFor(new MockHttpServletRequest("POST", "/api/v1/entries/batch")))
                .isEqualTo(1024 * 1024);
    }

    @Test
    void recognisesAnOversizedBodyBehindWrappingExceptions() {
        Exception wrapped = new IllegalStateException("read failed", new IOException("outer", new RequestBodyLimitFilter.BodyTooLargeException()));
        assertThat(RequestBodyLimitFilter.causedByTooLarge(wrapped)).isTrue();
        assertThat(RequestBodyLimitFilter.causedByTooLarge(new IOException("other"))).isFalse();
    }

    @Test
    void normalisesThePublicPathPrefix() {
        assertThat(PublicPathPrefixFilter.normalize("lockstep/")).isEqualTo("/lockstep");
        assertThat(PublicPathPrefixFilter.normalize("/lockstep")).isEqualTo("/lockstep");
        assertThat(PublicPathPrefixFilter.normalize(" ")).isEmpty();
    }
}
