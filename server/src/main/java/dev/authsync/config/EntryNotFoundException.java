package dev.authsync.config;

public class EntryNotFoundException extends RuntimeException {
    public EntryNotFoundException() {
        super("Authenticator entry not found");
    }
}

