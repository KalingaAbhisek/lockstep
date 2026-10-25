package dev.authsync.config;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Loads a local .env file as low-precedence Spring defaults. Real environment
 * variables and command-line arguments always win. This keeps production
 * configuration external while making local Maven runs predictable.
 */
public final class DotEnvLoader {
    private static final Set<String> SUPPORTED_KEYS = Set.of(
            "GOOGLE_WEB_CLIENT_ID",
            "GOOGLE_EXTENSION_CLIENT_ID",
            "ALLOWED_ORIGINS",
            "FIREBASE_PROJECT_ID",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "PORT", "TRUSTED_PROXIES", "SESSION_CACHE_SECONDS", "PUBLIC_PATH_PREFIX",
            "REAUTH_MAX_AGE_SECONDS", "REQUIRE_VAULT_REVISION", "ARGON2ID_WRAPPING", "REQUIRE_EDIT_BASE"
    );

    private DotEnvLoader() {}

    public static Map<String, Object> load() {
        Path workingDirectory = Path.of("").toAbsolutePath().normalize();
        Path envFile = findEnvFile(workingDirectory);
        if (envFile == null) return Map.of();
        try {
            Map<String, Object> values = new LinkedHashMap<>(
                    parse(Files.readAllLines(envFile, StandardCharsets.UTF_8)));
            Object credentials = values.get("GOOGLE_APPLICATION_CREDENTIALS");
            if (credentials instanceof String configuredPath) {
                Path path = Path.of(configuredPath);
                if (!path.isAbsolute()) {
                    values.put("GOOGLE_APPLICATION_CREDENTIALS",
                            envFile.getParent().resolve(path).normalize().toString());
                }
            }
            return Map.copyOf(values);
        } catch (IOException exception) {
            throw new IllegalStateException("Unable to read local configuration from " + envFile, exception);
        }
    }

    static Map<String, Object> parse(List<String> lines) {
        Map<String, Object> values = new LinkedHashMap<>();
        for (String originalLine : lines) {
            String line = originalLine.strip();
            if (line.isEmpty() || line.startsWith("#")) continue;
            if (line.startsWith("export ")) line = line.substring(7).strip();
            int separator = line.indexOf('=');
            if (separator <= 0) continue;
            String name = line.substring(0, separator).strip();
            if (!SUPPORTED_KEYS.contains(name)) continue;
            String value = unquote(line.substring(separator + 1).strip());
            if (!value.isBlank()) values.put(name, value);
        }
        return Map.copyOf(values);
    }

    private static Path findEnvFile(Path workingDirectory) {
        Path current = workingDirectory.resolve(".env");
        if (Files.isRegularFile(current)) return current;
        Path parent = workingDirectory.getParent();
        if (parent != null) {
            Path parentEnv = parent.resolve(".env");
            if (Files.isRegularFile(parentEnv)) return parentEnv;
        }
        return null;
    }

    private static String unquote(String value) {
        if (value.length() >= 2) {
            char first = value.charAt(0);
            char last = value.charAt(value.length() - 1);
            if ((first == '"' && last == '"') || (first == '\'' && last == '\'')) {
                return value.substring(1, value.length() - 1);
            }
        }
        return value;
    }
}

