package dev.authsync.session;

import dev.authsync.config.AuthSyncProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextHolderFilter;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

class ClientSessionValidationFilterTest {
    @Test
    void sessionDatabaseTimeoutReturnsRetryableServiceUnavailable() throws Exception {
        var broken=new ClientSessionRepository(){
            public void replace(String s,ClientType t,StoredSession v){}
            public Optional<StoredSession> find(String s,ClientType t){throw new dev.authsync.config.FirestoreCalls.DatabaseUnavailableException("timeout",null);}
        };
        var target=new ClientSessionValidationFilter(new ClientSessionService(broken,new AuthSyncProperties("web-client","extension-client","")));
        var response=send(target,"user-1",randomToken(),"127.0.0.4");
        assertThat(response.getStatus()).isEqualTo(503);
        assertThat(response.getHeader("Retry-After")).isEqualTo("30");
        assertThat(response.getContentAsString()).contains("BACKEND_UNAVAILABLE").doesNotContain("SESSION_REVOKED");
    }

    @Test
    void verifiedSessionGenerationIsBoundToBothGoogleAndSessionPrincipals() throws Exception {
        var google = googleJwt("user-1", "web-client");
        var registered = sessions.register(google, "web");
        var stored = repository.sessions.get("user-1:web");
        repository.sessions.put("user-1:web", new ClientSessionRepository.StoredSession(stored.tokenHash(), stored.email(), stored.displayName(), stored.expiresAt(), 7));
        for (boolean withGoogle : List.of(true, false)) {
            SecurityContextHolder.clearContext();
            if (withGoogle) SecurityContextHolder.getContext().setAuthentication(new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken(google));
            var request = new MockHttpServletRequest("DELETE", "/api/v1/entries/"+java.util.UUID.randomUUID());
            request.addHeader(ClientSessionValidationFilter.CLIENT_HEADER, "web");
            request.addHeader(ClientSessionValidationFilter.SUBJECT_HEADER, "user-1");
            request.addHeader(ClientSessionValidationFilter.SESSION_HEADER, registered.sessionToken());
            var response = new MockHttpServletResponse();
            AtomicReference<Jwt> principal = new AtomicReference<>();
            filter.doFilter(request, response, (ignoredRequest, ignoredResponse) -> principal.set((Jwt)SecurityContextHolder.getContext().getAuthentication().getPrincipal()));
            assertThat(dev.authsync.entry.AuthenticatedUser.generation(principal.get())).isEqualTo(7);
            if (withGoogle) {
                assertThat(principal.get().getIssuedAt()).isEqualTo(google.getIssuedAt());
                assertThat(principal.get().getHeaders().get("alg")).isEqualTo("RS256");
            } else assertThat(principal.get().getHeaders().get("alg")).isEqualTo(dev.authsync.config.RecentSignInPolicy.SESSION_TOKEN_ALGORITHM);
        }
    }

    @Test
    void deletesAndBatchesRecheckRevokedSessionsRatherThanUsingTheCache() throws Exception {
        AuthSyncProperties properties=new AuthSyncProperties("web-client","extension-client","");
        properties.setSessionCacheSeconds(60);
        ClientSessionService cached=new ClientSessionService(repository,properties);
        ClientSessionValidationFilter target=new ClientSessionValidationFilter(cached);
        String token=cached.register(googleJwt("user-1","web-client"),"web").sessionToken();
        repository.sessions.clear(); // Another instance revoked the session; this instance still has it cached.
        assertThat(send(target,"user-1",token,"198.51.100.40").getStatus()).isEqualTo(200);
        for (String method : List.of("DELETE","POST")) {
            SecurityContextHolder.clearContext();
            MockHttpServletRequest request=new MockHttpServletRequest(method,method.equals("POST")?"/api/v1/entries/batch":"/api/v1/entries/"+java.util.UUID.randomUUID());
            request.addHeader(ClientSessionValidationFilter.SUBJECT_HEADER,"user-1");
            request.addHeader(ClientSessionValidationFilter.CLIENT_HEADER,"web");
            request.addHeader(ClientSessionValidationFilter.SESSION_HEADER,token);
            MockHttpServletResponse response=new MockHttpServletResponse();
            target.doFilter(request,response,(ignoredRequest,ignoredResponse)->{});
            assertThat(response.getStatus()).isEqualTo(401);
        }
    }

    private final InMemoryRepository repository=new InMemoryRepository();
    private final ClientSessionService sessions=new ClientSessionService(
            repository,new AuthSyncProperties("web-client","extension-client",""));
    private final ClientSessionValidationFilter filter=new ClientSessionValidationFilter(sessions);

    @AfterEach
    void clearContext(){SecurityContextHolder.clearContext();}

    @Test
    void sessionCredentialAuthenticatesRequestsAfterGoogleCredentialIsGone()throws Exception{
        Jwt google=googleJwt("user-1","web-client");
        ClientSessionService.RegisteredSession registered=sessions.register(google,"web");
        MockHttpServletRequest request=new MockHttpServletRequest("GET","/api/v1/entries");
        request.addHeader(ClientSessionValidationFilter.SUBJECT_HEADER,"user-1");
        request.addHeader(ClientSessionValidationFilter.CLIENT_HEADER,"web");
        request.addHeader(ClientSessionValidationFilter.SESSION_HEADER,registered.sessionToken());
        MockHttpServletResponse response=new MockHttpServletResponse();
        AtomicReference<String> authenticatedSubject=new AtomicReference<>();

        FilterChainProxy securityChain=new FilterChainProxy(new DefaultSecurityFilterChain(
                AnyRequestMatcher.INSTANCE,
                new SecurityContextHolderFilter(new NullSecurityContextRepository()),
                filter,
                new AnonymousAuthenticationFilter("test-key"),
                new AuthorizationFilter(AuthenticatedAuthorizationManager.authenticated())));

        securityChain.doFilter(request,response,(ignoredRequest,ignoredResponse)->authenticatedSubject.set(
                ((Jwt)SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getSubject()));

        assertThat(response.getStatus()).isEqualTo(200);
        assertThat(authenticatedSubject).hasValue("user-1");
    }

    @Test
    void madeUpSessionsStopReachingFirestore()throws Exception{
        sessions.register(googleJwt("user-1","web-client"),"web");
        int before=repository.finds;
        // The same made-up token again and again: one Firestore read, then remembered as refused.
        String madeUp="A".repeat(43);
        for(int i=0;i<5;i++)assertThat(send("user-1",madeUp,"10.9.0.1").getStatus()).isEqualTo(401);
        assertThat(repository.finds-before).isEqualTo(1);
        // Malformed tokens and oversized account IDs are refused without any read.
        assertThat(send("user-1","not-a-session-token","10.9.0.2").getStatus()).isEqualTo(401);
        assertThat(send("x".repeat(300),madeUp,"10.9.0.2").getStatus()).isEqualTo(401);
        assertThat(repository.finds-before).isEqualTo(1);
    }

    @Test
    void anAddressSendingManyRefusedSessionsIsStoppedBeforeAnyLookup()throws Exception{
        String address="203.0.113.7";
        for(int i=0;i<FailedSessionLimiter.MAX_FAILURES_PER_MINUTE;i++){
            assertThat(send("user-"+i,randomToken(),address).getStatus()).isEqualTo(401);
        }
        int before=repository.finds;
        MockHttpServletResponse blocked=send("user-x",randomToken(),address);
        assertThat(blocked.getStatus()).isEqualTo(429);
        assertThat(repository.finds).isEqualTo(before);
        // Other addresses, and signed-in users elsewhere, are not affected.
        ClientSessionService.RegisteredSession registered=sessions.register(googleJwt("user-1","web-client"),"web");
        assertThat(send("user-1",registered.sessionToken(),"198.51.100.4").getStatus()).isEqualTo(200);
    }

    @Test
    void lookupsAlreadyInProgressCountTowardsTheLimit(){
        // Many requests at the same moment: each reserves its lookup before starting, so they cannot all pass.
        FailedSessionLimiter limiter=new FailedSessionLimiter();
        java.util.List<ClientSessionService.LookupGate> started=new java.util.ArrayList<>();
        for(int i=0;i<FailedSessionLimiter.MAX_FAILURES_PER_MINUTE;i++){
            ClientSessionService.LookupGate gate=limiter.gateFor("203.0.113.20");
            assertThat(gate.tryBegin()).isTrue();
            started.add(gate);
        }
        assertThat(limiter.gateFor("203.0.113.20").tryBegin()).isFalse();
        // A lookup that found a valid session frees its place; a refused one keeps it for the minute.
        started.get(0).end(false);
        assertThat(limiter.gateFor("203.0.113.20").tryBegin()).isTrue();
        started.get(1).end(true);
        assertThat(limiter.gateFor("203.0.113.20").tryBegin()).isFalse();
    }

    @Test
    void cachedSessionsKeepWorkingFromALimitedAddress()throws Exception{
        AuthSyncProperties cached=new AuthSyncProperties("web-client","extension-client","");
        cached.setSessionCacheSeconds(60);
        ClientSessionService cachingSessions=new ClientSessionService(repository,cached);
        ClientSessionValidationFilter cachingFilter=new ClientSessionValidationFilter(cachingSessions);
        String token=cachingSessions.register(googleJwt("user-1","web-client"),"web").sessionToken();
        String address="203.0.113.30";
        for(int i=0;i<FailedSessionLimiter.MAX_FAILURES_PER_MINUTE;i++){
            assertThat(send(cachingFilter,"user-"+i,randomToken(),address).getStatus()).isEqualTo(401);
        }
        assertThat(send(cachingFilter,"user-x",randomToken(),address).getStatus()).isEqualTo(429);
        // The signed-in user on the same network is served from the cache: no lookup, no limit.
        int before=repository.finds;
        assertThat(send(cachingFilter,"user-1",token,address).getStatus()).isEqualTo(200);
        assertThat(repository.finds).isEqualTo(before);
    }

    private MockHttpServletResponse send(String subject,String token,String address)throws Exception{
        return send(filter,subject,token,address);
    }

    private MockHttpServletResponse send(ClientSessionValidationFilter target,String subject,String token,String address)throws Exception{
        SecurityContextHolder.clearContext();
        MockHttpServletRequest request=new MockHttpServletRequest("GET","/api/v1/entries");
        request.setRemoteAddr(address);
        request.addHeader(ClientSessionValidationFilter.SUBJECT_HEADER,subject);
        request.addHeader(ClientSessionValidationFilter.CLIENT_HEADER,"web");
        request.addHeader(ClientSessionValidationFilter.SESSION_HEADER,token);
        MockHttpServletResponse response=new MockHttpServletResponse();
        target.doFilter(request,response,(ignoredRequest,ignoredResponse)->{});
        return response;
    }

    private static String randomToken(){
        byte[] random=new byte[32];
        new java.security.SecureRandom().nextBytes(random);
        return java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(random);
    }

    private static Jwt googleJwt(String subject,String audience){
        Instant now=Instant.now();
        return Jwt.withTokenValue("google-token")
                .header("alg","RS256")
                .subject(subject)
                .audience(List.of(audience))
                .issuedAt(now)
                .expiresAt(now.plusSeconds(3600))
                .claim("email","user@example.com")
                .claim("name","User")
                .build();
    }

    private static final class InMemoryRepository implements ClientSessionRepository {
        private final Map<String,StoredSession> sessions=new HashMap<>();
        int finds;

        @Override
        public void replace(String googleSubject,ClientType clientType,StoredSession session){
            sessions.put(googleSubject+":"+clientType.value(),session);
        }

        @Override
        public Optional<StoredSession> find(String googleSubject,ClientType clientType){
            finds++;
            return Optional.ofNullable(sessions.get(googleSubject+":"+clientType.value()));
        }
    }
}
