package dev.authsync.session;

import dev.authsync.config.RecentSignInPolicy;
import dev.authsync.vault.VaultResetService;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.jwt.Jwt;
import jakarta.servlet.http.Cookie;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

class ClientSessionControllerTest {
    @Test void signOutEverywhereReportsAConcurrentSignInInsteadOfClaimingSuccess() {
        var service=mock(ClientSessionService.class);
        when(service.parseClientType("web")).thenReturn(ClientType.WEB);
        var controller=new ClientSessionController(service,mock(VaultResetService.class),mock(RecentSignInPolicy.class));
        var request=new MockHttpServletRequest();request.addHeader(ClientSessionValidationFilter.SESSION_HEADER,"old-token");
        var jwt=Jwt.withTokenValue("test").header("alg","RS256").subject("owner").build();
        var response=controller.signOut(jwt,"web",true,request,new MockHttpServletResponse());
        assertThat(response.getStatusCode().value()).isEqualTo(409);
        assertThat(response.getBody().toString()).contains("SESSION_CHANGED");
    }
    @Test void signOutUsesTheRequestTokenAndCannotExpireANewerSignInCookie() {
        var service=mock(ClientSessionService.class);
        when(service.parseClientType("web")).thenReturn(ClientType.WEB);
        var controller=new ClientSessionController(service,mock(VaultResetService.class),mock(RecentSignInPolicy.class));
        var request=new MockHttpServletRequest();request.setCookies(new Cookie("__session","old-token"));
        var response=new MockHttpServletResponse();
        var jwt=Jwt.withTokenValue("test").header("alg","RS256").subject("owner").build();
        controller.signOut(jwt,"web",false,request,response);
        verify(service).revoke("owner",ClientType.WEB,false,"old-token");
        assertThat(response.getHeaders("Set-Cookie")).isEmpty();
    }
}
