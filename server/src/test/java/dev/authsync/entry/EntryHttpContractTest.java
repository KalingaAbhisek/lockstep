package dev.authsync.entry;

import dev.authsync.config.*;
import jakarta.validation.Validation;
import jakarta.validation.ValidatorFactory;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.validation.beanvalidation.SpringValidatorAdapter;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.UUID;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/** Check the HTTP/JSON contract with the patched Jackson family, real validation and exception mapping. */
class EntryHttpContractTest {
    private final EntryService service=mock(EntryService.class);
    private final Instant now=Instant.parse("2026-10-23T12:00:00Z");
    private ValidatorFactory validators;
    private MockMvc mvc;

    @BeforeEach
    void setUp() {
        validators=Validation.buildDefaultValidatorFactory();
        var controller=new EntryController(service,validators.getValidator(),new OperationRateLimiter(),
                new RecentSignInPolicy(new AuthSyncProperties("web","extension",""),Clock.fixed(now,ZoneOffset.UTC)));
        mvc=MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new ApiExceptionHandler())
                .setValidator(new SpringValidatorAdapter(validators.getValidator()))
                .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver()).build();
    }

    @AfterEach
    void close() { validators.close();SecurityContextHolder.clearContext(); }

    @Test
    void encryptedEntryRecordsRoundTripThroughJson() throws Exception {
        authenticate("RS256");
        UUID id=UUID.randomUUID(),mutation=UUID.randomUUID();
        when(service.put(any(),eq(id),any())).thenReturn(new EntryService.EntryResponse(id,"Encrypted","Encrypted","YQ==",
                "YQ==",1,"SHA1",6,30,1,2,mutation,null,null));
        mvc.perform(put("/api/v1/entries/"+id).contentType(MediaType.APPLICATION_JSON).content("""
                {"issuer":"Encrypted","accountName":"Encrypted","encryptedSecret":"YQ==","secretIv":"YQ==",
                "keyVersion":1,"algorithm":"SHA1","digits":6,"periodSeconds":30,"createdAtEpochMillis":1,
                "mutationId":"%s","baseMutationId":null}
                """.formatted(mutation)))
                .andExpect(status().isOk()).andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.mutationId").value(mutation.toString())).andExpect(jsonPath("$.encryptedSecret").value("YQ=="));
    }

    @Test
    void aSessionOnlyDeleteReturnsTheReauthenticationContract() throws Exception {
        authenticate(RecentSignInPolicy.SESSION_TOKEN_ALGORITHM);
        mvc.perform(delete("/api/v1/entries/"+UUID.randomUUID())).andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("REAUTH_REQUIRED"));
        verifyNoInteractions(service);
    }

    @Test
    void invalidEncryptedEntryIsRejectedBeforeServiceWork() throws Exception {
        authenticate("RS256");
        mvc.perform(put("/api/v1/entries/"+UUID.randomUUID()).contentType(MediaType.APPLICATION_JSON).content("{}"))
                .andExpect(status().isBadRequest()).andExpect(jsonPath("$.error").isString());
        verifyNoInteractions(service);
    }

    private void authenticate(String algorithm) {
        var jwt=Jwt.withTokenValue("test").header("alg",algorithm).subject("user").issuedAt(now).expiresAt(now.plusSeconds(3600)).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(jwt));
    }
}
