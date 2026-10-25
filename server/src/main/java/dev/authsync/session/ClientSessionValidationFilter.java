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
    private final FailedSessionLimiter failedSessions;

    @org.springframework.beans.factory.annotation.Autowired
    public ClientSessionValidationFilter(ClientSessionService sessions, FailedSessionLimiter failedSessions) {
        this.sessions = sessions;
        this.failedSessions = failedSessions;
    }

    public ClientSessionValidationFilter(ClientSessionService sessions) {
        this(sessions, new FailedSessionLimiter());
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return !path.startsWith("/api/")
                || path.equals("/api/v1/config")
                || path.equals("/api/v1/csp-report") && request.getMethod().equalsIgnoreCase("POST")
                || path.equals("/api/v1/session") && request.getMethod().equalsIgnoreCase("POST");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String sessionToken = sessionToken(request);
        // An address that keeps sending refused sessions gets no more session lookups (Firestore reads) for a
        // while; sessions found in the short cache are not affected.
        ClientSessionService.LookupGate gate = failedSessions.gateFor(request.getRemoteAddr());
        try {
            ClientSessionService.SessionValidation validation;
            boolean fresh=requiresFreshSession(request);
            if(authentication instanceof JwtAuthenticationToken jwtAuthentication){
                validation=sessions.validate(jwtAuthentication.getToken(),request.getHeader(CLIENT_HEADER),sessionToken,fresh,gate);
            }else{
                validation=sessions.validate(request.getHeader(SUBJECT_HEADER),request.getHeader(CLIENT_HEADER),sessionToken,fresh,gate);
            }
            if(validation.status()==ClientSessionService.SessionStatus.ACTIVE){
                var validated = validation.principal().orElseThrow();
                if(authentication instanceof JwtAuthenticationToken google){
                    Jwt original=google.getToken();
                    Jwt bound=Jwt.withTokenValue(original.getTokenValue()).headers(h->h.putAll(original.getHeaders()))
                            .claims(c->c.putAll(original.getClaims()))
                            .claim(dev.authsync.entry.AuthenticatedUser.GENERATION_CLAIM,validated.vaultGeneration()).build();
                    SecurityContext context=SecurityContextHolder.createEmptyContext();
                    context.setAuthentication(new JwtAuthenticationToken(bound,google.getAuthorities()));
                    SecurityContextHolder.setContext(context);
                }
                if(!(authentication instanceof JwtAuthenticationToken)){
                    var session=validation.principal().orElseThrow();
                    Instant now=Instant.now();
                    Jwt jwt=Jwt.withTokenValue(sessionToken)
                            .header("alg",dev.authsync.config.RecentSignInPolicy.SESSION_TOKEN_ALGORITHM)
                            .subject(session.subject())
                            .issuedAt(now)
                            .expiresAt(session.expiresAt())
                            .audience(List.of("lockstep-"+session.clientType().value()))
                            .claim("email",session.email())
                            .claim("email_verified",true)
                            .claim("name",session.displayName())
                            .claim(dev.authsync.entry.AuthenticatedUser.GENERATION_CLAIM,session.vaultGeneration())
                            .build();
                    SecurityContext context=SecurityContextHolder.createEmptyContext();
                    context.setAuthentication(new JwtAuthenticationToken(jwt,List.of()));
                    SecurityContextHolder.setContext(context);
                }
                chain.doFilter(request,response);
                return;
            }
            if(validation.status()==ClientSessionService.SessionStatus.RATE_LIMITED){
                response.setStatus(429);
                response.setHeader("Retry-After", "60");
                response.setContentType(MediaType.APPLICATION_JSON_VALUE);
                response.getWriter().write("{\"code\":\"RATE_LIMITED\",\"error\":\"Too many requests. Wait a minute and try again.\"}");
                return;
            }
            if(validation.status()==ClientSessionService.SessionStatus.EXPIRED){
                unauthorized(response,"SESSION_EXPIRED","Your 30-day Lockstep session has expired. Sign in with Google again.");
                return;
            }
        } catch (dev.authsync.config.FirestoreCalls.DatabaseUnavailableException unavailable) {
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
            response.setHeader("Retry-After","30");
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write("{\"code\":\"BACKEND_UNAVAILABLE\",\"error\":\"Lockstep is temporarily unavailable. Please try again in a moment.\"}");
            return;
        } catch (IllegalArgumentException ignored) {
            // A valid Google token with an ambiguous client audience cannot own an app session.
        }
        unauthorized(response,"SESSION_REVOKED",sessionToken==null||sessionToken.isBlank()
                ?"Sign in with Google to continue."
                :"This Lockstep session was replaced by a login on another device.");
    }

    /**
     * High-risk requests check the stored session instead of the short-lived cache: key rotation, vault
     * reset, entry deletion (including batches), lock changes and signing out of every device.
     */
    static boolean requiresFreshSession(HttpServletRequest request){
        String path=request.getRequestURI();
        String method=request.getMethod();
        if(path.equals("/api/v1/events")&&"GET".equalsIgnoreCase(method))return true;
        if(path.equals("/api/v1/vault/rotate")&&"POST".equalsIgnoreCase(method))return true;
        if(path.equals("/api/v1/vault")&&"DELETE".equalsIgnoreCase(method))return true;
        if(path.startsWith("/api/v1/entries/")&&"DELETE".equalsIgnoreCase(method))return true;
        if(path.equals("/api/v1/entries/batch")&&"POST".equalsIgnoreCase(method))return true;
        if(path.equals("/api/v1/lock")&&("PUT".equalsIgnoreCase(method)||"DELETE".equalsIgnoreCase(method)))return true;
        return path.equals("/api/v1/session")&&"DELETE".equalsIgnoreCase(method)&&"true".equalsIgnoreCase(request.getParameter("all"));
    }

    // The session token comes from the X-Lockstep-Session header, or (web app behind a same-origin proxy)
    // from the HttpOnly session cookie. Requests still need the X-Lockstep-Client header, which a
    // cross-site form or link cannot send, so the cookie cannot be used for cross-site request forgery.
    static String sessionToken(HttpServletRequest request){
        String header=request.getHeader(SESSION_HEADER);
        if(header!=null&&!header.isBlank())return header;
        if(request.getCookies()==null)return null;
        for(jakarta.servlet.http.Cookie cookie:request.getCookies()){
            if(ClientSessionController.isSessionCookie(cookie.getName())&&!cookie.getValue().isBlank())return cookie.getValue();
        }
        return null;
    }

    private static void unauthorized(HttpServletResponse response,String code,String message)throws IOException{
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getWriter().write("{\"code\":\""+code+"\",\"error\":\""+message+"\"}");
    }
}
