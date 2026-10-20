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

        @Override
        public void replace(String googleSubject,ClientType clientType,StoredSession session){
            sessions.put(googleSubject+":"+clientType.value(),session);
        }

        @Override
        public Optional<StoredSession> find(String googleSubject,ClientType clientType){
            return Optional.ofNullable(sessions.get(googleSubject+":"+clientType.value()));
        }
    }
}
