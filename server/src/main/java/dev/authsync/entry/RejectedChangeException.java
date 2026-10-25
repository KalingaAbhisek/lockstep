package dev.authsync.entry;

/**
 * A change the server refuses for good, with a machine-readable code (STALE_KEY, VAULT_RESET), so the
 * client drops it from its queue instead of retrying it forever. Answered with 400 like other bad input.
 */
public class RejectedChangeException extends IllegalArgumentException {
    private final String code;

    public RejectedChangeException(String message, String code) {
        super(message);
        this.code = code;
    }

    public String code() { return code; }
}
