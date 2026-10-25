package dev.authsync.config;

import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DotEnvLoaderTest {
    @Test
    void loadsRuntimeSecuritySettingsWithoutExposingBrowserOrUnknownSettings() {
        assertThat(DotEnvLoader.parse(List.of(
                "PORT=9090", "TRUSTED_PROXIES=10\\..*", "SESSION_CACHE_SECONDS=0",
                "PUBLIC_PATH_PREFIX=/lockstep", "REAUTH_MAX_AGE_SECONDS=120",
                "REQUIRE_VAULT_REVISION=true", "ARGON2ID_WRAPPING=true", "REQUIRE_EDIT_BASE=true",
                "LOCKSTEP_WEB_BASE_URL=https://example.com/lockstep", "GOOGLE_CLIENT_SECRET=never-used"
        ))).containsEntry("PORT", "9090")
                .containsEntry("SESSION_CACHE_SECONDS", "0")
                .containsEntry("REAUTH_MAX_AGE_SECONDS", "120")
                .containsEntry("REQUIRE_VAULT_REVISION", "true")
                .containsEntry("ARGON2ID_WRAPPING", "true")
                .containsEntry("REQUIRE_EDIT_BASE", "true")
                .doesNotContainKeys("LOCKSTEP_WEB_BASE_URL", "GOOGLE_CLIENT_SECRET");
    }

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

