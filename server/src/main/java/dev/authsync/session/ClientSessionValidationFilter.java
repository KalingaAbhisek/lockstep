package dev.authsync.session;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
@Component
public class ClientSessionValidationFilter extends OncePerRequestFilter {
    public static final String SESSION_HEADER = "X-Lockstep-Session";
    public static final String CLIENT_HEADER = "X-Lockstep-Client";
    private final ClientSessionService sessions;

    public ClientSessionValidationFilter(ClientSessionService sessions) {
        this.sessions = sessions;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/")
                || path.equals("/api/v1/config")
                || path.equals("/api/v1/session") && request.getMethod().equalsIgnoreCase("POST");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof JwtAuthenticationToken jwtAuthentication)) {
            chain.doFilter(request, response);
            return;
        }
        try {
            if (sessions.isActive(jwtAuthentication.getToken(), request.getHeader(CLIENT_HEADER), request.getHeader(SESSION_HEADER))) {
                chain.doFilter(request, response);
                return;
            }
        } catch (IllegalArgumentException ignored) {
            // A valid Google token with an ambiguous client audience cannot own an app session.
        }
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"code\":\"SESSION_REVOKED\",\"error\":\"This Lockstep session was replaced by a login on another device.\"}");
    }
}
