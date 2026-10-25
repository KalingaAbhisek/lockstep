package dev.authsync.entry;

import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;

/** A zero-knowledge record: the server never receives the plaintext TOTP seed. */
public final class AuthenticatorEntry {
    private final UUID id;
    private final String googleSubject;
    private final String issuer;
    private final String accountName;
    private final byte[] encryptedSecret;
    private final byte[] secretIv;
    private final int keyVersion;
    private final String algorithm;
    private final int digits;
    private final int periodSeconds;
    private final Instant createdAt;
    private final Instant updatedAt;
    private final UUID mutationId;
    // Optional: issuer and account name encrypted by the client (then issuer/accountName are placeholders).
    private final byte[] encryptedLabel;
    private final byte[] labelIv;

    public AuthenticatorEntry(UUID id, String googleSubject, String issuer, String accountName,
                              byte[] encryptedSecret, byte[] secretIv, int keyVersion, String algorithm,
                              int digits, int periodSeconds, Instant createdAt, Instant updatedAt,
                              UUID mutationId) {
        this(id, googleSubject, issuer, accountName, encryptedSecret, secretIv, keyVersion, algorithm,
                digits, periodSeconds, createdAt, updatedAt, mutationId, null, null);
    }

    public AuthenticatorEntry(UUID id, String googleSubject, String issuer, String accountName,
                              byte[] encryptedSecret, byte[] secretIv, int keyVersion, String algorithm,
                              int digits, int periodSeconds, Instant createdAt, Instant updatedAt,
                              UUID mutationId, byte[] encryptedLabel, byte[] labelIv) {
        this.id = id;
        this.googleSubject = googleSubject;
        this.issuer = issuer;
        this.accountName = accountName;
        this.encryptedSecret = Arrays.copyOf(encryptedSecret, encryptedSecret.length);
        this.secretIv = Arrays.copyOf(secretIv, secretIv.length);
        this.keyVersion = keyVersion;
        this.algorithm = algorithm;
        this.digits = digits;
        this.periodSeconds = periodSeconds;
        this.createdAt = createdAt;
        this.updatedAt = updatedAt;
        this.mutationId = mutationId;
        this.encryptedLabel = encryptedLabel == null ? null : Arrays.copyOf(encryptedLabel, encryptedLabel.length);
        this.labelIv = labelIv == null ? null : Arrays.copyOf(labelIv, labelIv.length);
    }

    public UUID getId() { return id; }
    public String getGoogleSubject() { return googleSubject; }
    public String getIssuer() { return issuer; }
    public String getAccountName() { return accountName; }
    public byte[] getEncryptedSecret() { return Arrays.copyOf(encryptedSecret, encryptedSecret.length); }
    public byte[] getSecretIv() { return Arrays.copyOf(secretIv, secretIv.length); }
    public int getKeyVersion() { return keyVersion; }
    public String getAlgorithm() { return algorithm; }
    public int getDigits() { return digits; }
    public int getPeriodSeconds() { return periodSeconds; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getUpdatedAt() { return updatedAt; }
    public UUID getMutationId() { return mutationId; }
    public byte[] getEncryptedLabel() { return encryptedLabel == null ? null : Arrays.copyOf(encryptedLabel, encryptedLabel.length); }
    public byte[] getLabelIv() { return labelIv == null ? null : Arrays.copyOf(labelIv, labelIv.length); }
}
