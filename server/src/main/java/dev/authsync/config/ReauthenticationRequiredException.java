package dev.authsync.config;

/** The request needs a Google sign-in from the last few minutes, not only a Lockstep session (403). */
public class ReauthenticationRequiredException extends RuntimeException {
    public ReauthenticationRequiredException() {
        super("Confirm it is you: sign in with Google again to continue.");
    }
}
