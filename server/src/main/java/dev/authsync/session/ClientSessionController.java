package dev.authsync.session;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/api/v1/session")
public class ClientSessionController {
    private final ClientSessionService sessions;

    public ClientSessionController(ClientSessionService sessions) { this.sessions = sessions; }

    @PostMapping
    ClientSessionService.RegisteredSession register(@AuthenticationPrincipal Jwt jwt,
                                                     @RequestHeader(ClientSessionValidationFilter.CLIENT_HEADER) String clientType) {
        return sessions.register(jwt, clientType);
    }

    @GetMapping
    Map<String, Object> status(@AuthenticationPrincipal Jwt jwt,
                               @RequestHeader(ClientSessionValidationFilter.CLIENT_HEADER) String clientType) {
        return Map.of("active", true, "clientType", sessions.clientType(jwt, clientType).value());
    }
}
