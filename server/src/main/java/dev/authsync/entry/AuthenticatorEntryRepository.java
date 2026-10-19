package dev.authsync.entry;

import java.util.List;
import java.util.UUID;

/** Persistence port implemented by the active storage adapter. */
public interface AuthenticatorEntryRepository {
    List<AuthenticatorEntry> findAllByGoogleSubject(String googleSubject);
    AuthenticatorEntry save(AuthenticatorEntry entry, AuthenticatedUser user);
    void deleteByIdAndGoogleSubject(UUID id, String googleSubject);
}

