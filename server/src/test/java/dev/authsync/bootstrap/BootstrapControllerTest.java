package dev.authsync.bootstrap;

import dev.authsync.config.AuthSyncProperties;
import dev.authsync.entry.EntryService;
import dev.authsync.lock.LockService;
import dev.authsync.vault.VaultChangedException;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.Jwt;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;
import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

class BootstrapControllerTest {
    private static LockService.AccountState state(long revision) {
        return new LockService.AccountState(true, new LockService.LockConfig(true,300,false,null,revision));
    }
    private static Jwt token() { return Jwt.withTokenValue("test").header("alg","RS256").subject("owner").build(); }

    @Test void rotationBetweenMetadataAndEntriesRetriesTheWholeRead() {
        var locks=mock(LockService.class);var entries=mock(EntryService.class);
        when(locks.accountState("owner")).thenReturn(state(1),state(2),state(2),state(2));
        when(entries.changes("owner",null)).thenReturn(new EntryService.Changes(List.of(),List.of(),10,false),
                new EntryService.Changes(List.of(),List.of(),20,true));
        var result=new BootstrapController(locks,entries,new AuthSyncProperties()).bootstrap(token(),null);
        assertThat(result.lock().vaultRevision()).isEqualTo(2);
        assertThat(result.cursor()).isEqualTo(20);
        assertThat(result.full()).isTrue();
    }

    @Test void continuouslyChangingVaultNeverReturnsMixedState() {
        var locks=mock(LockService.class);var entries=mock(EntryService.class);var revision=new AtomicLong();
        when(locks.accountState("owner")).thenAnswer(ignored->state(revision.incrementAndGet()));
        when(entries.changes("owner",null)).thenReturn(new EntryService.Changes(List.of(),List.of(),10,true));
        assertThatThrownBy(()->new BootstrapController(locks,entries,new AuthSyncProperties()).bootstrap(token(),null))
                .isInstanceOf(VaultChangedException.class);
        verify(entries,times(3)).changes("owner",null);
    }
}
