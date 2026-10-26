# Browser tests

Scenario tests for the web app (`webapp/`) and the Chrome extension (`extension/`) against a mock of the
Lockstep API (`mock-server.js`, which adds a 200 ms delay per request and mirrors the API's behaviour,
including the security headers, delta sync, deletion records, atomic rotation, server-side sign-out and
the HttpOnly cookie session behind a same-origin proxy).

From a fresh checkout, generate the public client files first. The example settings contain no credentials; browser scenarios replace the client configuration in temporary copies with mock API settings.

```powershell
./configure-clients.ps1 -EnvFile .env.example
./tools/test-env-config.ps1
cd tests/e2e
npm ci
npx playwright install chromium
npm test
```

`concurrency.test.js` runs both real vault modules with two browser tabs sharing IndexedDB. It covers
rotation fencing, stale replies after deletion, simultaneous ordinary writes, persistent upload sequence
allocation and dependent edits queued while the clock moves backwards (including legacy queues),
plus recovery of intervening offline creates when Web Locks are unavailable. `web-concurrency` holds
the rotation response open and verifies that another tab preserves refused add-account form inputs,
then accepts the account after unlocking with the rotated key.
The shared concurrency suite also checks delayed key acknowledgements against newer pending wrappers,
malformed server IDs and transaction rollback after an IndexedDB clone failure. The deletion/integrity
scenarios check long-label confirmation dialogs, editing a 1,000-card list and expiry bars under reduced motion.

It also pauses recovery import inside key derivation to verify that explicit locking cancels it without
changing the persisted key. `auth-boundaries.test.js` exercises the worker's real request/cleanup helpers
against delayed success and 401 responses after a newer sign-in. `web-concurrency` covers the corresponding
race between two real tabs. The rendering scenarios verify expired-code copying; extension integrity also
checks QR pixel bounds and bitmap cleanup on rejection.

Covered: startup and reload requests, offline use, unlock and wrong passphrase, session replacement,
passphrase never sent, Content-Security-Policy violations, delta sync, encrypted account names, atomic
recovery-key rotation (including a refused one), sign-out, cookie mode, old-server fallbacks, and that web
pages cannot use the extension's privileged actions. The mock API listens on `API_PORT` (default `18080`, so a Lockstep API running locally on 8080 is not in the
way), and the runner waits until it is actually listening. `WEBAPP_DIR=<dir>` tests a built copy of the web app
(for example the minified files). Trusted Types are enforced in the tests. `web-argon2id-reauth` covers Argon2id
re-protection after unlock, the Google confirmation dialog (including a different Google account), a reset, and
codes appearing before a slow server answers. Like the API, the mock has Argon2id and the vault-revision
requirement on by default; `web-main-pbkdf2` and `extension-main-pbkdf2` repeat the main flows with Argon2id
switched off (`ARGON2ID=0`), and every scenario fails if an app sends a key change without the vault revision.
`web-rotation-stale` and `extension-rotation-stale` rotate the recovery key on a device that has not seen
another device re-protect the key (the server's vault revision moved on); the extension one also checks that a
vault created right after the worker restarted uses Argon2id. `web-vault-replaced` and `extension-vault-replaced`
cover a server vault that was deleted and set up again from another device while this device still holds the
older one: it switches by itself when nothing would be lost, and otherwise asks first (keeping its older vault,
without syncing, until the user chooses). `web-export` covers the passphrase check before a backup or recovery-key download, the password-encrypted
backup (no readable secret in the file) and importing it again with its password. `web-revision` covers two devices: a device with a
fast clock cannot overwrite a newer passphrase, a stale passphrase change is refused, the saved delta cursor,
refused changes being dropped, the rotation guard, the sealed session key and "sign out of all devices".
`web-integrity` covers an edit refused because the account changed (CONFLICT) or was deleted (DELETED) on
another device, a refused queued change that must not block the next one, an over-long secret, a damaged
account shown as an error next to working ones, names with non-ASCII letters, the system dark theme, keyboard
focus surviving a code change and error messages that go away. `extension-integrity` covers a lock pressed
while an unlock is still running, the sealed session key after a worker restart, that a silently renewed
Google token cannot reset the vault, a damaged account, the version shown in Settings and the sync queue.
Google sign-in is replaced by a stub.

The Firestore transaction rules (concurrent saves, rotation against a passphrase change, reset against a save,
rotations of more than 500 accounts) are tested against the Firestore emulator by
`server/src/test/java/dev/authsync/vault/FirestoreEmulatorTest.java`:

```powershell
npx firebase-tools emulators:exec --project demo-lockstep --only firestore "mvn -B -pl server -am test -Dtest=FirestoreEmulatorTest"
```

`sync-faults.test.js` exercises captured sync identities, timeout normalization, Retry-After parsing, and jittered retry scheduling. `auth-boundaries.test.js` also verifies that a queued request carrying an old authentication snapshot is rejected before fetch.

`startup-boundaries.test.js` covers account switches during bootstrap and older-server fallbacks, plus cooldowns imposed after retry timers are created. The extension offline scenario verifies a queued upload waits for its outage cooldown, then advances that deadline to test recovery without a long CI delay.

Cross-tab sign-out is covered by `web-concurrency.test.js` with the network offline. Shared crypto concurrency checks verify that a tab missing notifications cannot recreate erased records. Backend `ResetEnumerationTest` checks blocked enumeration timeout and bounded collection traversal.

`backup-boundaries.test.js` checks extension import account-switch/lock cancellation, 1,000-entry plaintext/encrypted export round trips with long Unicode labels, oversized entry-count rejection, and final light-theme CSS contrast in both clients.

`image-import.test.js` verifies size/header limits before decoder allocation, requested resize dimensions, and bitmap cleanup for both shared helpers. The shared concurrency test also covers valid recovery when the first twenty entries are damaged; rotation-metadata tests retain stale-wrapper and pending-change protections.

`unlock-races.test.js` pauses cryptographic work and erases/recreates the vault from another tab. It checks passphrase unlock, legacy migration, session resume, and concurrent snapshot exports. Set both `API_PORT` and `WEB_PORT_BASE` to distinct ranges when running independent browser suites in parallel.

`ui-session-boundaries.test.js` verifies stale refresh/UI callbacks and superseded Google callbacks. The import boundary tests exercise account switching and locking in both clients.

The UI session-boundary suite also checks extension list replies and authentication errors arriving after a lock/sign-out, retained edit-draft cleanup, and settings animations interrupted by locking. The extension integrity browser scenario delays a real decrypted list reply until after locking and verifies zero rendered or retained rows. The shared unlock-race suite pauses secret reads, locks and unlocks again, then verifies old account-list, QR, backup and recovery-key operations are refused.

`./tools/test-env-config.ps1` verifies repeated builds after `.env` edits, relative input/output paths with a different .NET working directory, rejection of partially valid imports without changing any terminal variables, explicit reload with `-OverrideExisting`, environment precedence, secret isolation and generated extension permissions/CSP.

The startup-boundary tests exercise a failed background web upload that records Retry-After and ensure the retry runner retains that cooldown. They also switch accounts during a retry and verify the older task cannot overwrite the newer account's pending count.

`cross-client-live-sync` uses a real extension worker/popup and webapp against one mock API. It checks additions, edits, deletions and shared lock settings in both directions using focus and the actual periodic-refresh callbacks (with the interval accelerated only in the fixture). It also rotates from each client and unlocks the opposite client without navigation or reload.

Reconnect uploads: the webapp schedules its encrypted outbox immediately on the browser online event. An open extension popup notifies the worker to reset transient network backoff and schedule upload immediately; the worker also listens for online events and retains its retry timer/alarm for a closed popup. Browser suspension can delay background work. Explicit server Retry-After still takes precedence. Reconnect tests cover the popup open and the popup closed with a locked vault; acknowledged writes leave the queue without a reload or unlock.

The reconnect scenarios also queue an account addition and an edit while offline, then compare the acknowledged mutation and encrypted label with the server copy after reconnection. The extension case checks both a locked vault with no popup and immediate upload notified by an open popup. No manual retry, reload or unlock is used to upload queued ciphertext.

`snapshot-sync.test.js` verifies that routine reads in both clients use the revision-fenced bootstrap snapshot and reject old-view results when the key rotates, the account changes, or the account is missing. Settings-navigation and local-code-refresh callbacks are also delayed across lock/recovery transitions to verify that old callbacks cannot expose navigation buttons or clear a newer busy flag.

`import-staging.test.js` delays file reads, the last QR animation frame and password-dialog completion across cancellation/view changes. It checks both late success and failure, duplicate-submit prevention and recovery-file selection ordering. `wrapping-bounds.test.js` intercepts expensive derivation calls to prove corrupt local wrappers are refused before KDF work, then restores the valid wrapper and unlocks it normally.

Cross-client scenarios added in this review (all run by `run-all.js`):

- `cross-client-conflicts.test.js`: the web app and the extension rename, delete, add, change the passphrase and rotate the recovery key at the same moment; server, web app and extension must converge exactly (IDs, versions, names, nothing queued, nothing undecryptable).
- `session-replacement.test.js`: one web and one extension session per Google account (mock `perClientSessions` mode, like the API). A second web or extension sign-in signs out only the matching client at once and clears its keys; two simultaneous web sign-ins leave exactly one valid session.
- `live-tabs.test.js`: four web app tabs and the extension popup open at once. The tabs share one live connection, every change reaches every tab and the popup within about a second, another tab takes over when the listening one closes, and a sign-in elsewhere signs out every tab. Run also against an API that refuses extra connections (`live-tabs-old-server`) and with tabs that cannot share (`live-tabs-unshared`, where the API must make room for the popup).
- `popup-closed.test.js`: the web app rotates the recovery key, then changes the passphrase, then another extension signs in, each while the extension popup is closed; the popup must open to the lock screen (old passphrase refused, new one accepted) or the sign-in screen without ever showing a code, and the replaced extension must drop its key.
- `web-away.test.js`: the same for the web app: while its tab is on another site (keeping its saved unlocked session), the extension rotates the key, then changes the passphrase, then another web app signs in; on return the web app opens to the lock or sign-in screen without showing a code, and opens straight to the codes when nothing changed.
- `account-deleted.test.js`: the account is deleted on the server while both clients hold its vault. The extension shows sign-in, then stays on "create passphrase" (watched for 35 seconds, past the popup's 30-second background check) and opens the new empty vault; the web app refuses the deleted vault's passphrase, accepts the new one and shows only the new vault's accounts. Then the same with the web app creating the passphrase and the extension unlocking it.
- `stale-google-token.test.js` (also run as `no-google-token`): Google's sign-in token has expired (or is gone after a browser restart), as in normal use after an hour; passphrase changes and key rotations in each direction must lock the other client without ever showing "sign in with Google", and the new passphrase must work. It then repeats a passphrase change while the other client opens during temporary server failures (`failNext` in the mock): no sign-in screen, locked as soon as the server answers.
- `offline-retry.test.js`: an account scanned offline shows its code at once and uploads as soon as the device is online; while the server is unreachable, queued changes are retried every 5 to 10 seconds in both clients. It also selects a QR code in a web page with the extension's real scanner while offline and checks the in-page notice and the later upload, and checks that a download that failed while online (with nothing to upload) is retried within 5 to 10 seconds in the web app and the extension popup.
- `cross-client-keys.test.js`: rotation and passphrase changes in both directions through each client's screens; the other client locks, rejects the old passphrase, accepts the new one and supports every operation, including rotating again.
- `cross-client-restore.test.js`: "Forgot passphrase" (restore with the recovery key) in the web app and in the extension. The restoring client opens with the new passphrase and, after locking, refuses the old one; the other client locks within seconds (or, if it was closed, opens locked), refuses the old passphrase and accepts the new one; lock settings (auto-lock time, lock on screen lock) are kept; every operation works afterwards.
- `cross-client-pending.test.js`: a passphrase change is held to exactly the same standard as a key rotation, in both directions. The other client is cut off from the server (mock `blockClient`) and adds an account while the change happens elsewhere; on reconnecting it locks (key and saved session gone, no codes shown, every operation refused), refuses the old passphrase, opens with the current one, uploads the account it added while cut off (nothing left "only on this device"), and every operation then works on both clients.
