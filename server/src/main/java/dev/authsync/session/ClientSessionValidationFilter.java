package dev.authsync.session;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
@Component
public class ClientSessionValidationFilter extends OncePerRequestFilter {
    public static final String SESSION_HEADER = "X-Lockstep-Session";
    public static final String CLIENT_HEADER = "X-Lockstep-Client";
    public static final String SUBJECT_HEADER = "X-Lockstep-Subject";
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
        try {
            ClientSessionService.SessionValidation validation;
            if(authentication instanceof JwtAuthenticationToken jwtAuthentication){
                validation=sessions.validate(jwtAuthentication.getToken(),request.getHeader(CLIENT_HEADER),request.getHeader(SESSION_HEADER));
            }else{
                validation=sessions.validate(request.getHeader(SUBJECT_HEADER),request.getHeader(CLIENT_HEADER),request.getHeader(SESSION_HEADER));
            }
            if(validation.status()==ClientSessionService.SessionStatus.ACTIVE){
                if(!(authentication instanceof JwtAuthenticationToken)){
                    var session=validation.principal().orElseThrow();
                    Instant now=Instant.now();
                    Jwt jwt=Jwt.withTokenValue(request.getHeader(SESSION_HEADER))
                            .header("alg","LOCKSTEP-SESSION")
                            .subject(session.subject())
                            .issuedAt(now)
                            .expiresAt(session.expiresAt())
                            .audience(List.of("lockstep-"+session.clientType().value()))
                            .claim("email",session.email())
                            .claim("email_verified",true)
                            .claim("name",session.displayName())
                            .build();
                    SecurityContext context=SecurityContextHolder.createEmptyContext();
                    context.setAuthentication(new JwtAuthenticationToken(jwt,List.of()));
                    SecurityContextHolder.setContext(context);
                }
                chain.doFilter(request,response);
                return;
            }
            if(validation.status()==ClientSessionService.SessionStatus.EXPIRED){
                unauthorized(response,"SESSION_EXPIRED","Your 30-day Lockstep session has expired. Sign in with Google again.");
                return;
            }
        } catch (IllegalArgumentException ignored) {
            // A valid Google token with an ambiguous client audience cannot own an app session.
        }
        unauthorized(response,"SESSION_REVOKED","This Lockstep session was replaced by a login on another device.");
    }

    private static void unauthorized(HttpServletResponse response,String code,String message)throws IOException{
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"code\":\""+code+"\",\"error\":\""+message+"\"}");
    }
}
