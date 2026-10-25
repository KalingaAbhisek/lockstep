package dev.authsync.session;

import dev.authsync.config.PublicPathPrefixFilter;
import dev.authsync.config.RecentSignInPolicy;
import dev.authsync.vault.VaultResetService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/session")
public class ClientSessionController {
    /** Web clients that reach the API through a same-origin proxy can ask for an HttpOnly cookie. */
    public static final String SESSION_MODE_HEADER = "X-Lockstep-Session-Mode";
    public static final String SESSION_COOKIE = "lockstep_session";
    /** Firebase Hosting forwards only a cookie with this name to Cloud Run. */
    public static final String FIREBASE_SESSION_COOKIE = "__session";
    // The API's own path. The nginx proxy maps it to the browser's path (e.g. /lockstep/api).
    private static final String COOKIE_PATH = "/api";
    private final ClientSessionService sessions;
    private final VaultResetService resets;
    private final RecentSignInPolicy recentSignIn;

    public ClientSessionController(ClientSessionService sessions, VaultResetService resets, RecentSignInPolicy recentSignIn) {
        this.sessions = sessions;
        this.resets = resets;
        this.recentSignIn = recentSignIn;
    }

    @PostMapping
    ClientSessionService.RegisteredSession register(@AuthenticationPrincipal Jwt jwt,
                                                     @RequestHeader(ClientSessionValidationFilter.CLIENT_HEADER) String clientType,
                                                     @RequestHeader(value = SESSION_MODE_HEADER, required = false) String mode,
                                                     HttpServletRequest request, HttpServletResponse response) {
        resets.beforeSignIn(jwt.getSubject()); // no new session while a vault reset is deleting the old one
        ClientSessionService.RegisteredSession registered = sessions.register(jwt, clientType);
        if ("cookie".equalsIgnoreCase(mode) && "web".equals(registered.clientType())) {
            // The token goes only into an HttpOnly cookie that page scripts cannot read.
            Duration lifetime = Duration.ofMillis(Math.max(0, registered.expiresAtEpochMillis() - Instant.now().toEpochMilli()));
            response.addHeader(HttpHeaders.SET_COOKIE, cookie(request, registered.sessionToken(), lifetime).toString());
            return new ClientSessionService.RegisteredSession(null, registered.clientType(), registered.expiresAtEpochMillis());
        }
        return registered;
    }

    @GetMapping
    Map<String, Object> status(@RequestHeader(ClientSessionValidationFilter.CLIENT_HEADER) String clientType) {
        return Map.of("active", true, "clientType", sessions.parseClientType(clientType).value());
    }

    /** Server-side sign-out for this client, or for every client of the account with {@code ?all=true}. */
    @DeleteMapping
    ResponseEntity<?> signOut(@AuthenticationPrincipal Jwt jwt,
                 @RequestHeader(ClientSessionValidationFilter.CLIENT_HEADER) String clientType,
                 @RequestParam(name = "all", defaultValue = "false") boolean all,
                 HttpServletRequest request, HttpServletResponse response) {
        if (all) recentSignIn.require(jwt); // signing out every device needs a recent Google sign-in
        boolean revoked = sessions.revoke(jwt.getSubject(), sessions.parseClientType(clientType), all, ClientSessionValidationFilter.sessionToken(request));
        // Revocation makes the old cookie unusable. Do not expire cookies in this response: it could
        // arrive after a newer sign-in's Set-Cookie and erase that new session. A new sign-in replaces it.
        if (all && !revoked) return ResponseEntity.status(HttpStatus.CONFLICT).body(Map.of(
                "code", "SESSION_CHANGED", "error", "Your sign-in changed. Sign in again before signing out of all devices."));
        return ResponseEntity.noContent().build();
    }

    /** Accepts the cookie set through either route (nginx proxy or Firebase Hosting rewrite). */
    public static boolean isSessionCookie(String name) {
        return SESSION_COOKIE.equals(name) || FIREBASE_SESSION_COOKIE.equals(name);
    }

    // Through the nginx proxy the cookie is set for /api (nginx rewrites the path). Through Firebase Hosting
    // (the request arrived under the public prefix) it gets the browser-side path and Firebase's cookie name.
    private static ResponseCookie cookie(HttpServletRequest request, String value, Duration maxAge) {
        Object prefix = request.getAttribute(PublicPathPrefixFilter.PREFIX_ATTRIBUTE);
        boolean viaPrefix = prefix instanceof String text && !text.isEmpty();
        return ResponseCookie.from(viaPrefix ? FIREBASE_SESSION_COOKIE : SESSION_COOKIE, value)
                .httpOnly(true).secure(true).sameSite("Strict").path(viaPrefix ? prefix + COOKIE_PATH : COOKIE_PATH)
                .maxAge(maxAge).build();
    }
}
