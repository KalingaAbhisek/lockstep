package dev.authsync.config;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Minimal health check for Cloud Run startup and liveness probes. It answers once the application has
 * started and never touches Firestore, so probes cost nothing. (A plain controller instead of Spring Boot
 * Actuator keeps startup as fast as before; the path matches Actuator's, so switching later changes nothing.)
 */
@RestController
public class HealthController {
    private static final Map<String, String> UP = Map.of("status", "UP");

    @GetMapping("/actuator/health")
    Map<String, String> health() { return UP; }
}
