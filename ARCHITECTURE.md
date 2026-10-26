# Lockstep architecture

## Trust boundary

```text
Chrome extension ─┐
                  ├─ local AES-256-GCM vault + local TOTP generation
Static web/PWA ───┘                 │
                                    ├─ IndexedDB encrypted replica and outbox
                                    └─ HTTPS + Google ID token ─> Spring Boot API ─> Firestore ciphertext
```

The clients parse authenticator URIs, encrypt seeds, generate verification codes, render transfer QR images, and export backups locally. The server never receives a plaintext seed, recovery key, or generated code.

## Security and storage decisions

1. Google `sub` is the tenant key. Every Firestore path is selected from the verified JWT subject, never from request data.
2. Entry and mutation identifiers are independently generated UUIDv4 values. UUID entropy is defense in depth; authenticated tenant scoping is the authorization boundary.
3. The passphrase never leaves the device. The server stores only lock preferences and the wrapped (passkey-encrypted) vault key; clients check a passphrase by unwrapping that key locally. Verifiers stored by older versions are deleted the next time the account is read. New or changed passphrases need at least 12 characters.
   Each user has a client-generated 256-bit vault master key. IndexedDB retains only a wrapped copy encrypted with AES-256-GCM under a passphrase-derived key: PBKDF2-HMAC-SHA-256 (random 128-bit salt, 600,000 iterations) or Argon2id (64 MiB, 3 passes) once switched on. The unwrapped key remains only in client memory while unlocked. AES-GCM entry keys are derived locally per version with HKDF-SHA256. The public version number is not secret and reveals nothing without the master key. Associated data is `lockstep:v2:<subject>:<entry-id>:<key-version>`.
4. Firestore stores ciphertext, 96-bit IVs, key version, TOTP parameters, encrypted issuer/account labels (placeholders in the plain fields), UUIDs, and timestamps.
5. IndexedDB retains encrypted entries for offline code generation. A transactional outbox retains idempotent PUT or DELETE operations until acknowledged. One upload runs at a time per account, also across browser tabs (Web Locks). A change the server refuses for good (STALE_KEY, VAULT_RESET, CONFLICT, DELETED, or any other 400/413) leaves the queue so it cannot block later changes, the user is told, and the next sync downloads the full list. A refused new account (for example over the account limit, ACCOUNT_LIMIT) is not thrown away: it stays on the device only ("kept locally"), so its secret is never lost; recovery-key rotation waits until such accounts are exported or removed; the apps show them as "Only on this device" (not counted as synchronized) with an "upload again" action. If the recovery key is rotated on another device while this one still has accounts added offline with the old key, the old wrapped key is kept (`retired-master` record) until those accounts have been re-encrypted with the new key after the next unlock, so they are never lost. If the passphrase was changed too, such an account shows "Open it with the passphrase you used then" and is re-encrypted once that passphrase is entered. An account kept locally whose ID turns up in the server's list (for example a retry refused because it had been changed elsewhere) takes the server's copy again. Imports are checked against the server's limits before anything is saved. An account that cannot be decrypted is listed with an error instead of a code (never deleted), so it cannot hide the others.
13. The vault code (`crypto-store.js`) is a single file shared by the web app and the extension; CI checks that both copies are identical. Locking increments a per-account generation that aborts in-flight writes and unlocks, so a lock always wins over an unlock that is still running. The unlocked key kept for page reloads (web) or worker restarts (extension) is sealed with a non-extractable AES key stored in IndexedDB.
14. Actions that need recent Google confirmation (entry deletion, reset, rotation, passphrase change, sign-out everywhere) use the existing Google flow. The server verifies token issue time; the extension additionally tracks interactive sign-ins and never counts silent renewal as confirmation. This does not force Google Account reauthentication. Deletion and reset also verify the existing vault passphrase locally; no device passkeys are enrolled.
6. Both clients refresh the device-reported internet state every 10 seconds and react immediately to browser connectivity events. Lockstep API/session health is checked separately so a server problem cannot incorrectly label the device itself Offline.
7. Recovery keys are client-side exports. Both clients download one automatically after successful first-time profile/passphrase setup and allow additional manual downloads. Losing all provisioned devices and every recovery key makes the vault unrecoverable. "Forgot passphrase" works from the lock screen of either client (the vault does not have to be unlocked): after a recent Google confirmation the recovery key is checked against the encrypted accounts, the master key is wrapped with the new passphrase and saved with `PUT /api/v1/lock`, keeping the existing lock settings. The other client sees the new wrapped key and locks, exactly as after a passphrase change.
8. Rotation creates a new random 256-bit vault master key, increments the public version and re-encrypts every entry in memory. `POST /api/v1/vault/rotate` writes the new wrapped key and all re-encrypted entries in one Firestore transaction, refusing (409) if the server's entries differ from what the client re-encrypted; only then does the client store the result. It produces a new recovery key and invalidates the previous one. While it runs, the client accepts no other local change.
12. The user document carries a vault revision that the server increments whenever the wrapped key changes (passphrase change, rotation, reset). Clients send the revision they last saw with every key change and the server refuses a stale one (409); the server's wrapped key always wins, and device clocks are never compared. The same document holds the account count, updated in the same transaction as every entry change, so the 1,000-account limit holds under concurrent saves. A vault reset first replaces the user document with a reset marker, so requests already in flight fail instead of re-creating data.
9. Pin state and explicit ordering are device-local and never sent to the API.
10. QR transfer and plain-text backup deliberately reveal plaintext locally after a disclosure warning and, for backups and recovery-key downloads, the vault passphrase. An encrypted backup is JSON `{format: "lockstep-encrypted-backup", version: 1, wrapping, iterations, memoryKiB?, parallelism?, salt, iv, ciphertext}`: the plain backup text encrypted with AES-256-GCM (additional data `lockstep:backup:v1`) under a key derived from a separate backup password with Argon2id (64 MiB, 3 passes) or, where Argon2id cannot load, PBKDF2-SHA-256 (600,000 rounds); import refuses parameters no Lockstep app writes. No third-party QR service is used.
11. The API issues a random, hashed server-side client session after Google authentication. Signing out deletes it on the server (`DELETE /api/v1/session`, `?all=true` for every client). Behind the optional same-origin proxy the web app keeps it in an HttpOnly cookie instead of `localStorage`. Each session has a fixed 30-day lifetime measured from that Google sign-in; API activity and silent Google credential renewal do not extend it. Each Google subject has one `web` slot and one `extension` slot. A new login replaces only the matching slot, and every authenticated API request validates the subject, client channel, session token, and fixed expiry.

## Request and offline flow

```text
Add:
  parse locally -> UUIDv4 -> AES-GCM encrypt -> IndexedDB entry + outbox transaction
  -> render/generate locally -> PUT encrypted record when authenticated connectivity succeeds

Open:
  GET /api/v1/bootstrap (account status + lock settings + encrypted records in one request)
  -> render encrypted IndexedDB replica immediately -> process outbox -> merge the bootstrap records locally

List:
  render encrypted IndexedDB replica immediately -> process outbox (POST /api/v1/entries/batch when
  several changes are queued) -> GET encrypted server records -> merge locally -> decrypt and generate
  codes locally. A new 30-second code is generated locally without a server request.

Edit:
  update local metadata -> queue full encrypted PUT carrying baseMutationId (the version it was made from)
  -> synchronize; the server refuses it with CONFLICT if the entry changed since, or DELETED if it was
  removed, instead of overwriting the newer state (last writer no longer wins). With REQUIRE_EDIT_BASE (default
  on) an update without baseMutationId is refused as well (older apps drop it and ask to update).
  Deletes have no precondition on purpose: a deletion wins over a concurrent edit on another device.
  Each change counts against a per-account limit of 1,200 changes a minute (a batch counts all its changes).

Delete:
  verify local passphrase + recent Google confirmation -> online authenticated DELETE
  -> remove local replica and older queued uploads only after server acknowledgement
  The deleted UUID remains reserved; delayed original creates cannot resurrect it.

Rotate:
  sync -> generate new vault master -> wrap with verified passphrase -> re-encrypt in memory
  -> POST /api/v1/vault/rotate (one transaction) -> store locally -> download new recovery key
```

## Firestore schema

```text
users/{google-subject}
  googleSubject, email, displayName, profileUpdatedAt, schemaVersion = 2
  lockTimeoutSeconds, lockOnScreenLock
  wrappedVaultKey, wrappedVaultKeyVersion, wrappedVaultKeyCreatedAt, wrappedVaultKeyUpdatedAt,
  wrappedVaultKeyAlgorithm   ("PBKDF2-SHA256/AES-256-GCM" or "ARGON2ID-V13/AES-256-GCM"),
  wrappedVaultKeyIterations  (PBKDF2 rounds, or Argon2id passes), wrappedVaultKeySalt, wrappedVaultKeyIv,
  wrappedVaultKeyMemoryKiB, wrappedVaultKeyParallelism   (Argon2id only)
  vaultRevision      (incremented whenever the wrapped key changes or the vault is reset)
  vaultGeneration    (incremented only by reset; late authenticated mutations from older generations are refused)
  entryCount         (number of entry documents, updated in the same transaction as every entry change)
  vaultResetAt, vaultResetStatus   ("IN_PROGRESS" while a reset deletes the old vault, then "COMPLETE")
  vaultResetLease   (random ID of the one request cleaning up; an interrupted reset is taken over by exactly one sign-in)
  clientSessions/{web|extension}
    tokenHash
    email
    displayName
    expiresAt
    updatedAt
    vaultGeneration  (captured transactionally when the session is issued)
    schemaVersion = 3
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
    encryptedLabel, labelIv   (issuer and account name, encrypted; the plain fields hold "Encrypted")
    schemaVersion = 2
  deletedEntries/{uuid-v4}
    deletedAt          (tombstone so other devices learn about deletions in a delta sync)
    schemaVersion      (2; UUID reservations persist until a vault reset, with no TTL)
    schemaVersion = 2
```

Only `authenticatorEntries.updatedAt` and `deletedEntries.deletedAt` are indexed (`firestore.indexes.json`);
every other field is exempt, which keeps writes small and fast.

Clients sync deltas: `GET /api/v1/bootstrap` and a full `GET /api/v1/entries/changes` return a cursor, and later syncs call `GET /api/v1/entries/changes?since=<cursor>` to receive only changed entries and deleted IDs. A full list still runs at least every 30 minutes. The cursor is also saved on the device, so reopening the app sends `GET /api/v1/bootstrap?since=<cursor>`; the server answers with the full list for cursors older than 36 hours.

Reopening the app (or the extension popup) shows the codes already on the device (or the lock screen) without waiting for the server. The startup answer is checked before the first sync uses it: a deleted account signs out, and a key changed on another device locks the vault.

Resetting the vault, rotating the recovery key, replacing the wrapped key and signing out of every device need a Google ID token issued within `REAUTH_MAX_AGE_SECONDS` (default 5 minutes); a session-only request gets 403 `REAUTH_REQUIRED`, and the apps then ask the user to confirm with Google.

The passphrase-derived wrapping key is PBKDF2-SHA-256 (600,000 rounds) or, while `ARGON2ID_WRAPPING` is on (the default), Argon2id (64 MiB, 3 passes, RFC 9106) from `vendor/argon2id.js` (openpgpjs/argon2id, rebuilt by `tools/argon2id/build.sh` and checked against the RFC test vectors by `tools/argon2id/verify.js`). Existing PBKDF2 keys are re-protected with Argon2id after the next unlock.

The web app and extension build all markup with DOM calls (no HTML strings). The extension enforces Trusted Types; the web app reports violations (`Content-Security-Policy-Report-Only`), and the browser tests enforce them.

The Firebase Admin SDK bypasses Firestore Security Rules, so the API must validate Google tokens and construct every collection path from the verified subject. It must validate ciphertext and metadata sizes without attempting decryption.

## Operational boundaries

- Terminate TLS at the application or trusted proxy.
- Keep the Firebase service account outside the repository and grant minimum required permissions.
- Configure exact web and extension origins in `ALLOWED_ORIGINS`.
- Deploy `webapp/` and `server/` independently. Configure public client values in the root `.env` and run `./configure-clients.ps1` to generate ignored browser configuration and the extension manifest. Containers receive `LOCKSTEP_API_BASE_URL` and other public frontend values at runtime; production API configuration is supplied separately. Never place Firebase credentials in a frontend or extension deployment.
- Never log request bodies for encrypted-entry writes because metadata can still be sensitive.
- Back up Firestore ciphertext and user metadata together. Recovery still requires the user's recovery key.
- Lock protection gates access to decrypted vault material and invalidates in-flight read/export operations. Local device and OS security remain part of the threat model.

The extension invalidates its view generation on lock, sign-out and recovery. Delayed replies and navigation animations cannot repopulate decrypted rows or hide a newer lock screen. Shared account-list, QR and export reads also capture the vault lock generation and check it before returning secrets, including when the vault has already been unlocked again.

Live shared-data refresh: current servers advertise `liveChanges` and provide an authenticated `/api/v1/events` SSE channel. Active webapp pages and extension popups fetch authoritative vault state as changes arrive, including additions, edits, deletions, passphrase/recovery-key changes and shared lock settings. Account writes commit a `changeSequence` notification marker in the same Firestore transaction; document listeners deliver changes across API instances. Notifications contain no vault data or credentials, and session credentials stay in request headers or the same-origin HttpOnly cookie. A changed key locks the receiving client and requires the current passphrase. Draft inputs remain intact unless a key/session change requires closing sensitive views; encrypted records can synchronize while editing. The 30-second timer and focus checks remain as fallback for older servers, interrupted streams and suspended clients. Reconnecting streams receive an initial invalidation to catch missed changes. The web app's tabs share one stream per browser (a Web Lock picks the listening tab, a BroadcastChannel passes its events to the others), and a full account makes room by closing its oldest stream of the same client type, so neither client is shut out of live changes by the other's tabs or by streams a closed popup left behind. A closed extension popup has no stream, and neither has a web app tab that went to another site or was reopened with its saved unlocked session. When either opens online with the vault still unlocked, it shows codes only after its startup check has answered (at most 1.5 s), so a rotation, passphrase change or sign-in made elsewhere meanwhile opens the lock or sign-in screen without a code ever appearing. Offline, the device's vault opens at once. When a client takes a different vault key from the server (rotation, passphrase change, or an account deleted and created again), its next sync downloads the full list instead of the changes since its last sync: a vault created anew has no deletion records for the accounts of the one it replaced, and only the full list removes them. Only a refused or expired session (or a deleted account) sends a client to "sign in with Google": a "session ended" event on the live connection is confirmed with one request first (a session that is still valid simply reconnects), and a startup or lock-settings request that fails for a temporary reason (a busy or briefly unreachable server) leaves the client on the screen its own vault calls for (locked, or open within the lock timeout), retrying in 5 to 10 seconds; the web app also remembers whether the server offers live updates, so such a failure does not cost it its live connection. While the passphrase is being created there is no vault to check, so background lock checks wait until it exists (otherwise they would answer "locked" and replace the setup screen with "unlock"). Theme, pins and account order remain device-local. A change that arrives while the receiving client is in edit mode or has a dialog open is stored at once and shown as soon as editing ends or the dialog closes; a confirmation interrupted by a lock always counts as cancelled. Deploy the backend, redeploy the webapp, and rebuild/release the extension to enable live updates on both clients.

Routine delta synchronization on current servers now uses `/api/v1/bootstrap` for wrapped-key metadata and ciphertext together. The server fences the response with vault revision checks, preventing a rotation between separate reads from mixing key and account versions. This replaces the separate lock-settings request during ordinary sync; older servers retain the legacy fallback. Startup still reuses its prefetched response. A changed key locks the receiving client before account decryption. Responses older than the locally known vault revision are rejected before cached lock settings or account ciphertext can be applied. If an account update and its tombstone overlap in one delta, deletion takes precedence in the API response and both client stores.

File-import cancellation: backup/QR preprocessing is tied to its originating vault view, and late recovery-file reads cannot refill a cleared form or replace a newer selection. Backup-password dialogs accept only one submission at a time; cancelled derivations cannot reset or close a later dialog. Both clients validate supported wrapping algorithms, salt size and bounded integer KDF parameters before starting derivation, including local vault records; valid encryption settings are unchanged.
