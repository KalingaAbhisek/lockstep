package dev.authsync.config;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DotEnvLoaderTest {
    @Test
    void parsesSupportedValuesAndIgnoresRemovedServerEncryptionKey() {
        Map<String, Object> result = DotEnvLoader.parse(List.of(
                "# local settings",
                "AUTHSYNC_ENCRYPTION_KEY=abc123==",
                "export GOOGLE_WEB_CLIENT_ID=web.apps.googleusercontent.com",
                "ALLOWED_ORIGINS=\"http://localhost:8080,chrome-extension://abc\"",
                "UNKNOWN_VALUE=ignored"
        ));

        assertThat(result).containsEntry("GOOGLE_WEB_CLIENT_ID", "web.apps.googleusercontent.com")
                .containsEntry("ALLOWED_ORIGINS", "http://localhost:8080,chrome-extension://abc")
                .doesNotContainKey("AUTHSYNC_ENCRYPTION_KEY")
                .doesNotContainKey("UNKNOWN_VALUE");
    }
}

