package dev.authsync.session;

public enum ClientType {
    WEB("web"),
    EXTENSION("extension");

    private final String value;

    ClientType(String value) { this.value = value; }

    public String value() { return value; }
}
