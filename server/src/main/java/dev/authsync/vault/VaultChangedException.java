package dev.authsync.vault;

/** The vault changed on the server since the client prepared its key rotation. */
public class VaultChangedException extends RuntimeException {
    public VaultChangedException(String message) { super(message); }
}
