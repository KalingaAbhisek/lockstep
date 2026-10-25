package dev.authsync.session;

import com.google.cloud.Timestamp;
import com.google.cloud.firestore.*;
import dev.authsync.config.ApiExceptionHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicReference;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

class VaultChangeControllerTest {
    private final Firestore firestore=mock(Firestore.class);
    private final CollectionReference users=mock(CollectionReference.class), sessions=mock(CollectionReference.class);
    private final DocumentReference user=mock(DocumentReference.class), session=mock(DocumentReference.class);
    private final ListenerRegistration profileRegistration=mock(ListenerRegistration.class), sessionRegistration=mock(ListenerRegistration.class);
    private final AtomicReference<EventListener<DocumentSnapshot>> profileListener=new AtomicReference<>(), sessionListener=new AtomicReference<>();
    private VaultChangeController controller;
    private MockMvc mvc;
    private Jwt principal() { return Jwt.withTokenValue("google-token").header("alg","RS256").subject("alice")
            .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600)).build(); }
    @BeforeEach void setup() {
        when(firestore.collection("users")).thenReturn(users);when(users.document("alice")).thenReturn(user);
        when(user.collection("clientSessions")).thenReturn(sessions);when(sessions.document("web")).thenReturn(session);
        when(user.addSnapshotListener(org.mockito.ArgumentMatchers.<EventListener<DocumentSnapshot>>any())).thenAnswer(call->{profileListener.set(call.getArgument(0));return profileRegistration;});
        when(session.addSnapshotListener(org.mockito.ArgumentMatchers.<EventListener<DocumentSnapshot>>any())).thenAnswer(call->{sessionListener.set(call.getArgument(0));return sessionRegistration;});
        controller=new VaultChangeController(firestore);
        mvc=MockMvcBuilders.standaloneSetup(controller).setControllerAdvice(new ApiExceptionHandler())
                .setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver()).build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(principal()));
    }
    @AfterEach void cleanup(){controller.shutdown();SecurityContextHolder.clearContext();}

    @Test void authenticatedStreamContainsOnlyInvalidationsAndClosesOnSessionReplacement() throws Exception {
        var result=mvc.perform(get("/api/v1/events").header("X-Lockstep-Client","web").header("X-Lockstep-Session","secret-session"))
                .andExpect(request().asyncStarted()).andExpect(header().string("Cache-Control","no-store"))
                .andExpect(header().string("X-Accel-Buffering","no")).andReturn();
        var valid=mock(DocumentSnapshot.class);when(valid.exists()).thenReturn(true);
        when(valid.getString("tokenHash")).thenReturn(VaultChangeController.hash("secret-session"));
        when(valid.getTimestamp("expiresAt")).thenReturn(Timestamp.ofTimeSecondsAndNanos(Instant.now().plusSeconds(3600).getEpochSecond(),0));
        sessionListener.get().onEvent(valid,null);
        profileListener.get().onEvent(mock(DocumentSnapshot.class),null);
        await(()->result.getResponse().getContentAsString().contains("event:change"));
        assertThat(result.getResponse().getContentAsString()).doesNotContain("secret-session","google-token","alice");
        var replaced=mock(DocumentSnapshot.class);when(replaced.exists()).thenReturn(true);when(replaced.getString("tokenHash")).thenReturn("different");
        sessionListener.get().onEvent(replaced,null);
        await(()->result.getResponse().getContentAsString().contains("event:session"));
        result.getAsyncResult(2000);
        verify(profileRegistration).remove();verify(sessionRegistration).remove();
        verify(users).document("alice");
    }

    @Test void fullAccountClosesItsOldestConnectionInsteadOfRefusingTheNewOne() {
        // Usually a closed popup or reloaded page whose disconnect the server has not noticed yet; refusing would
        // keep the newest client off live changes for the Retry-After minute.
        var request=new MockHttpServletRequest("GET","/api/v1/events");request.addHeader("X-Lockstep-Client","web");request.addHeader("X-Lockstep-Session","session");
        for(int i=0;i<4;i++)controller.events(principal(),request,new MockHttpServletResponse());
        verify(profileRegistration,never()).remove();
        assertThatCode(()->controller.events(principal(),request,new MockHttpServletResponse())).doesNotThrowAnyException();
        verify(profileRegistration,times(1)).remove();verify(sessionRegistration,times(1)).remove();
        controller.shutdown();verify(profileRegistration,times(5)).remove();verify(sessionRegistration,times(5)).remove();
    }

    @Test void partialListenerSetupFailureReleasesItsReservation() {
        when(user.addSnapshotListener(org.mockito.ArgumentMatchers.<EventListener<DocumentSnapshot>>any())).thenThrow(new IllegalStateException("watch unavailable"));
        var request=new MockHttpServletRequest("GET","/api/v1/events");request.addHeader("X-Lockstep-Client","web");request.addHeader("X-Lockstep-Session","session");
        for(int i=0;i<6;i++)assertThatThrownBy(()->controller.events(principal(),request,new MockHttpServletResponse()))
                .isInstanceOf(IllegalStateException.class).hasMessage("watch unavailable");
        verify(sessionRegistration,times(6)).remove();
    }

    @Test
    @org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable(named="FIRESTORE_EMULATOR_HOST",matches=".+")
    void independentApiInstancesReceiveCommittedEditsAndSessionRevocation() throws Exception {
        try(var database=FirestoreOptions.newBuilder().setProjectId("demo-lockstep")
                .setEmulatorHost(System.getenv("FIRESTORE_EMULATOR_HOST")).build().getService()) {
            String owner="live-"+java.util.UUID.randomUUID();
            var profile=database.collection("users").document(owner);
            var expires=Timestamp.ofTimeSecondsAndNanos(Instant.now().plusSeconds(3600).getEpochSecond(),0);
            var batch=database.batch();batch.set(profile,java.util.Map.of("googleSubject",owner,"entryCount",0L));
            for(String type:java.util.List.of("web","extension"))batch.set(profile.collection("clientSessions").document(type),
                    java.util.Map.of("tokenHash",VaultChangeController.hash(type+"-live"),"expiresAt",expires,"vaultGeneration",0L));
            batch.commit().get();
            var first=new VaultChangeController(database);var second=new VaultChangeController(database);
            try {
                var principal=Jwt.withTokenValue("google-token").header("alg","RS256").subject(owner)
                        .issuedAt(Instant.now()).expiresAt(Instant.now().plusSeconds(3600)).build();
                SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(principal));
                var firstMvc=MockMvcBuilders.standaloneSetup(first).setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver()).build();
                var secondMvc=MockMvcBuilders.standaloneSetup(second).setCustomArgumentResolvers(new AuthenticationPrincipalArgumentResolver()).build();
                var web=firstMvc.perform(get("/api/v1/events").header("X-Lockstep-Client","web").header("X-Lockstep-Session","web-live")).andReturn();
                var extension=secondMvc.perform(get("/api/v1/events").header("X-Lockstep-Client","extension").header("X-Lockstep-Session","extension-live")).andReturn();
                await(()->count(web.getResponse().getContentAsString())>0&&count(extension.getResponse().getContentAsString())>0);
                int webBefore=count(web.getResponse().getContentAsString()),extensionBefore=count(extension.getResponse().getContentAsString());
                var repository=new dev.authsync.entry.FirestoreAuthenticatorEntryRepository(database);
                var user=new dev.authsync.entry.AuthenticatedUser(owner,null,null);
                java.util.UUID id=java.util.UUID.randomUUID();Instant now=Instant.now();
                var created=new dev.authsync.entry.AuthenticatorEntry(id,owner,"Encrypted","Encrypted",new byte[32],new byte[12],1,"SHA1",6,30,now,now,java.util.UUID.randomUUID());
                repository.save(created,user);
                await(()->count(web.getResponse().getContentAsString())>webBefore&&count(extension.getResponse().getContentAsString())>extensionBefore);
                int webCreated=count(web.getResponse().getContentAsString()),extensionCreated=count(extension.getResponse().getContentAsString());
                var edited=new dev.authsync.entry.AuthenticatorEntry(id,owner,"Encrypted","Encrypted",new byte[32],new byte[12],1,"SHA1",6,30,now,Instant.now(),java.util.UUID.randomUUID());
                repository.save(edited,user,created.getMutationId());
                await(()->count(web.getResponse().getContentAsString())>webCreated&&count(extension.getResponse().getContentAsString())>extensionCreated);
                assertThat(profile.get().get().getLong("changeSequence")).isEqualTo(2);
                assertThat(profile.collection("authenticatorEntries").document(id.toString()).get().get().getString("mutationId")).isEqualTo(edited.getMutationId().toString());
                profile.collection("clientSessions").document("web").delete().get();
                await(()->web.getResponse().getContentAsString().contains("event:session"));
                web.getAsyncResult(3000);
                assertThat(extension.getResponse().getContentAsString()).doesNotContain("event:session");
            } finally {
                first.shutdown();second.shutdown();database.recursiveDelete(profile).get();
            }
        }
    }

    private static int count(String content) { return content.split("event:change",-1).length-1; }

    private static void await(java.util.concurrent.Callable<Boolean> condition) throws Exception {
        long deadline=System.nanoTime()+java.time.Duration.ofSeconds(10).toNanos();
        while(!condition.call()){if(System.nanoTime()>deadline)throw new AssertionError("Notification did not arrive");Thread.sleep(10);}
    }
}
