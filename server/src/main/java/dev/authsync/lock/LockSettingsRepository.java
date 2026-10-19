package dev.authsync.lock;

import java.util.Optional;

public interface LockSettingsRepository {
    Optional<LockSettings> find(String googleSubject);
    void save(String googleSubject, LockSettings settings);
    void delete(String googleSubject);
}
