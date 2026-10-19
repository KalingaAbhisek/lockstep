# Lockstep architecture

## Trust boundary

```text
Chrome extension ─┐
                  ├─ local AES-256-GCM vault + local TOTP generation
Mobile web/PWA ───┘                 │
                                    ├─ IndexedDB encrypted replica and outbox
                                    └─ HTTPS + Google ID token ─> Spring Boot API ─> Firestore ciphertext
```

The clients parse authenticator URIs, encrypt seeds, generate verification codes, render transfer QR images, and export backups locally. The server never receives a plaintext seed, encryption key, recovery key, or generated code.

## Security and storage decisions

1. Google `sub` is the tenant key. Every Firestore path is selected from the verified JWT subject, never from request data.
2. Entry and mutation identifiers are independently generated UUIDv4 values. UUID entropy is defense in depth; authenticated tenant scoping is the authorization boundary.
3. Each user has a client-generated 256-bit vault master key. IndexedDB retains only a wrapped copy encrypted with AES-256-GCM under a PBKDF2-HMAC-SHA-256 passphrase-derived key (random 128-bit salt, 600,000 iterations). The unwrapped key remains only in client memory while unlocked. AES-GCM entry keys are derived locally per version with HKDF-SHA256. The public version number is not secret and reveals nothing without the master key. Associated data is `lockstep:v2:<subject>:<entry-id>:<key-version>`.
4. Firestore stores ciphertext, a 96-bit IV, key version, TOTP parameters, display metadata, UUIDs, and timestamps.
5. IndexedDB retains encrypted entries for offline code generation. A transactional outbox retains idempotent PUT or DELETE operations until acknowledged.
6. `navigator.onLine` is only a hint. Synchronization is confirmed by authenticated API requests and retried on startup, focus, visibility changes, and online events.
7. Recovery keys are explicit client-side exports. Losing all provisioned devices and every recovery key makes the vault unrecoverable.
8. Rotation creates a new random 256-bit vault master key, increments the public version, re-encrypts locally, publishes the new wrapped key before replacement ciphertext, and queues idempotent entry updates. It produces a new recovery key and invalidates the previous one.
9. Pin state and explicit ordering are device-local and never sent to the API.
10. QR transfer and text backup deliberately reveal plaintext locally after a disclosure warning. No third-party QR service is used.

## Request and offline flow

```text
Add:
  parse locally -> UUIDv4 -> AES-GCM encrypt -> IndexedDB entry + outbox transaction
  -> render/generate locally -> PUT encrypted record when authenticated connectivity succeeds

List:
  render encrypted IndexedDB replica immediately -> process outbox -> GET encrypted server records
  -> merge locally -> decrypt and generate codes locally

Edit:
  update local metadata -> queue full encrypted PUT -> synchronize

Delete:
  delete local replica -> queue idempotent DELETE scoped by authenticated subject -> synchronize

Rotate:
  generate new vault master -> wrap with verified passkey -> re-encrypt locally
  -> publish wrapped key -> queue PUTs -> synchronize -> download new recovery key
```

## Firestore schema

```text
users/{google-subject}
  authenticatorEntries/{uuid-v4}
    issuer
    accountName
    encryptedSecret
    secretIv
    keyVersion
    algorithm
    digits
    periodSeconds
    createdAt
    updatedAt
    mutationId
    schemaVersion = 2
```

The Firebase Admin SDK bypasses Firestore Security Rules, so the API must validate Google tokens and construct every collection path from the verified subject. It must validate ciphertext and metadata sizes without attempting decryption.

## Operational boundaries

- Terminate TLS at the application or trusted proxy.
- Keep the Firebase service account outside the repository and grant minimum required permissions.
- Configure exact web and extension origins in `ALLOWED_ORIGINS`.
- Never log request bodies for encrypted-entry writes because metadata can still be sensitive.
- Back up Firestore ciphertext and user metadata together. Recovery still requires the user's recovery key.
- App Lock is a presentation/privacy layer; local device and OS security remain part of the threat model.
