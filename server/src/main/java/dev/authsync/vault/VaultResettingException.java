package dev.authsync.vault;

/** A vault reset is still deleting data; sign-in and passphrase setup wait until it finishes (409). */
public class VaultResettingException extends RuntimeException {
    public VaultResettingException() {
        super("Your vault is being reset. Try again in a minute.");
    }
}
