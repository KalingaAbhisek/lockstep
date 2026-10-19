package dev.authsync.config;

import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.concurrent.TimeUnit;

@RestController
public class PublicConfigController {
    private final AuthSyncProperties properties;

    public PublicConfigController(AuthSyncProperties properties) {
        this.properties = properties;
    }

    @GetMapping("/api/v1/config")
    ResponseEntity<Map<String, String>> config() {
        String clientId = properties.googleWebClientId() == null ? "" : properties.googleWebClientId();
        return ResponseEntity.ok()
                .cacheControl(CacheControl.maxAge(1, TimeUnit.HOURS).cachePublic())
                .body(Map.of("googleClientId", clientId));
    }
}

