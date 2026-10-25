# Lockstep

Lockstep consists of a Spring Boot synchronization API, a separately deployable mobile-first PWA, and a Manifest V3 Chrome extension. The extension can capture the visible tab, let the user select a QR-code region, and synchronize the new TOTP entry with the phone web app.

## Repository layout

```text
server/       Spring Boot API and encrypted Firestore persistence
webapp/       Standalone static PWA and optional Nginx container
extension/    Unpacked Manifest V3 Chrome extension
ARCHITECTURE.md  Security and system-design decisions
```

## Prerequisites

- JDK 21+
- A Firebase project with a Cloud Firestore database
- One Google OAuth **Web application** client shared by the PWA and extension web-auth flow

## Configure Google sign-in

1. In Google Cloud Console, configure the OAuth consent screen.
2. Create a **Web application** OAuth client. Add `http://localhost:5173` as an authorized JavaScript origin.
   Google does not accept an HTTP LAN address such as `http://192.168.x.x:8080` as a web OAuth origin. Phone access must use an HTTPS hostname and that exact origin must also be registered.
3. Load the extension once and copy its extension ID from `chrome://extensions`.
4. On the Web application OAuth client from step 2, add this exact authorized redirect URI, replacing `<extension-id>` with the copied ID:

   ```text
   https://<extension-id>.chromiumapp.org/google
   ```

   The scheme, extension ID, path, and absence of a trailing slash must match exactly. A Google OAuth client of type **Chrome Extension** cannot be used by this implementation because it signs in through `chrome.identity.launchWebAuthFlow` and requests an OpenID Connect ID token.
5. Copy `.env.example` to `.env`. Set `GOOGLE_WEB_CLIENT_ID`, `GOOGLE_EXTENSION_CLIENT_ID`, `LOCKSTEP_API_BASE_URL` and `LOCKSTEP_WEB_BASE_URL`, then run `./configure-clients.ps1`. Both client configs and the extension API permissions/CSP are generated from these values.
6. Give the API that ID as both `GOOGLE_WEB_CLIENT_ID` and `GOOGLE_EXTENSION_CLIENT_ID`.
7. If the consent screen is in **Testing**, add the Google account used for sign-in under **Test users**.

Google's stable `sub` claim—not email—is used as the database owner ID.

## Configure Firebase

1. In the [Firebase console](https://console.firebase.google.com/), create or select a project.
2. Open **Build → Firestore Database**, create the database, and choose Native mode.
3. In Google Cloud IAM, create a dedicated service account and grant only **Cloud Datastore User** (`roles/datastore.user`).
4. For local development, sign in once with your own Google account instead of downloading a key file: `gcloud auth application-default login` (your account needs Firestore access in the project). `run-local.ps1` uses these credentials when `GOOGLE_APPLICATION_CREDENTIALS` is blank.
5. Put the Firebase project ID in the root `.env`:

   ```dotenv
   FIREBASE_PROJECT_ID=your-project-id
   ```

   A service-account JSON key still works (`GOOGLE_APPLICATION_CREDENTIALS=secrets/firebase-service-account.json`), but a long-lived key is riskier; if you used one before, consider deleting it in Google Cloud IAM.

The service account is used only by the Spring Boot server. Never place its JSON file in the web app or extension. In production on Google Cloud, leave `GOOGLE_APPLICATION_CREDENTIALS` unset and use an attached service account instead of a long-lived JSON key.

## Run locally

The easiest backend run creates a Git-ignored `.env` for Google and Firebase configuration:

```powershell
.\run-local.ps1
```

Then add the two Google client IDs and the Firebase variables described above to `.env`, and run the same command again. The application loads `.env` automatically whether Maven starts from the repository root or the `server` directory. Operating-system environment variables and command-line arguments override `.env` values.

To configure the variables manually:

```powershell
$env:GOOGLE_WEB_CLIENT_ID = "your-web-client-id.apps.googleusercontent.com"
$env:GOOGLE_EXTENSION_CLIENT_ID = "your-web-client-id.apps.googleusercontent.com"
$env:ALLOWED_ORIGINS = "http://localhost:5173,chrome-extension://your-extension-id"
$env:FIREBASE_PROJECT_ID = "your-project-id"
$env:GOOGLE_APPLICATION_CREDENTIALS = "secrets/firebase-service-account.json"
./mvnw.cmd spring-boot:run -pl server
```

In a second terminal, build and run the Nginx frontend container, then open <http://localhost:5173/lockstep/>:

```powershell
docker build -t lockstep-webapp webapp
docker run --rm -p 5173:8080 -e LOCKSTEP_API_BASE_URL=http://host.docker.internal:8080 lockstep-webapp
```

Run `./configure-clients.ps1` after editing `.env` and before serving the static webapp or loading/reloading the extension. Generated `webapp/config.js`, `extension/config.js` and `extension/manifest.json` are ignored by Git; edit `.env` and `extension/manifest.template.json`, not generated files. The frontend container reads environment variables at startup; it never includes `.env` in its image.

When using the frontend container locally, copy only the public frontend settings from `.env` into an ignored `.env.frontend` and pass it with `docker run --env-file .env.frontend`. Never pass backend credentials to the frontend container. Cloud Run and other hosting platforms do not automatically read the local `.env`; configure the same variable on the frontend service.

Firestore creates a real document for each Google account at `users/{google-subject}` (with verified email/display metadata when supplied by Google), and stores that user's encrypted TOTP records below `users/{google-subject}/authenticatorEntries/{entry-id}`.

## Load the extension

1. Open `chrome://extensions` and enable Developer mode.
2. Run `./configure-clients.ps1`, then choose **Load unpacked** and select the `extension` directory. The generated manifest permits only the configured API origin. Reload the extension after regenerating configuration.
3. Add the resulting extension origin (`chrome-extension://<id>`) to `ALLOWED_ORIGINS`, comma-separated with the web origin, then restart the server.
4. Sign in from the popup. Use the scan toolbar button, drag around a TOTP QR code on the current tab, and confirm it appears in both clients.

QR recognition uses the bundled scanner and does not depend on Chrome's `BarcodeDetector`. The result of a tab scan is shown as a short notice on the page (never a blocking browser dialog); an account scanned offline is added at once and uploads when the device is back online. In edit mode, the `+` button offers four additive ways to add accounts: scan a selected region of the current tab, enter a standard TOTP account manually, decode one or more local QR images, or paste one or more `otpauth://` URLs. Manual entries support 6, 7 or 8 digits, SHA-1/SHA-256/SHA-512, and a configurable period. Unsupported counter-based and provider-specific formats are displayed as unavailable rather than being saved incorrectly.

The popup follows the operating system's light/dark preference and also supports an explicit theme override. Its edit mode supports renaming, deleting, and drag-reordering accounts. Pinning is a local Chrome preference, so it moves an account to the top without an API request and does not change another device's layout. The QR button intentionally reveals a scannable copy of an entry, so use it only in private and close it when finished.

Both clients support editing, device-local ordering and pinning, scannable QR transfer, and additive backup import/export. A backup is either a password-encrypted `.json` file (Argon2id and AES-256-GCM, opened again with that password) or the plain `.txt` format with one standard `otpauth://totp/...` URI per line for moving to other authenticator apps. Exporting a backup or downloading the recovery key asks for the vault passphrase again. Importing adds entries and never deletes or replaces existing entries; duplicate URIs are therefore imported as separate entries. Plain-text exports contain usable TOTP secrets and must be protected like passwords (Downloads folders are often synced to cloud storage).

The web app uses the camera scanner on mobile devices. On laptops and desktop computers, the same action opens the browser's screen-sharing picker; the user drags around a QR code in the local preview before it is decoded.

TOTP seeds are encrypted with a per-user AES-256-GCM key before they leave the browser. Firestore receives only ciphertext (the secret and, separately, the issuer and account name), random IVs, a key version, and TOTP parameters; code generation, QR generation, and backup export happen locally. When first-time profile and passphrase setup completes, Lockstep automatically downloads the recovery-key file; **Download recovery key** remains available for additional copies. Store the current file offline. A new device signs in with Google, downloads the passphrase-wrapped vault key from the server, and unlocks it with the same passphrase; the recovery key is needed only if the passphrase is forgotten or that wrapped key is unavailable. If you forget the Lockstep passphrase, use **Forgot passphrase?** and the current recovery key to create a new passphrase.

IndexedDB stores only an AES-256-GCM-wrapped vault master key. A local wrapping key is derived from the Lockstep passphrase with PBKDF2-HMAC-SHA-256 using a random 128-bit salt and 600,000 iterations, or (by default, see `ARGON2ID_WRAPPING` in `DEPLOYMENT.md`) with the memory-hard Argon2id (64 MiB, 3 passes), which makes guessing a passphrase from a stolen copy far more expensive; while the vault is unlocked, the extension keeps the unwrapped master key in memory (and in memory-only `chrome.storage.session`), and the web app also keeps an encrypted copy in the tab's `sessionStorage` so a reload does not ask for the passphrase again. That copy is sealed with a per-tab AES key that cannot be exported from the browser and is kept in IndexedDB; both are cleared when the vault locks or on sign-out, and the copy ends when the tab closes. Locking, signing out, closing/restarting the client, or making the PWA inactive clears that in-memory key. A key version is merely public derivation context and is safe to expose, but possession of the master/recovery key permits derivation of every version and therefore compromises the entire vault.

The PWA and extension retain an encrypted IndexedDB replica. Accounts added or edited without connectivity are usable immediately and an idempotent UUIDv4 operation is placed in the local outbox. Startup, refresh, focus, and reconnection attempt to upload pending operations. A queue item is removed only after the API acknowledges it, while the encrypted local entry remains available for offline code generation.

The Online/Offline indicator refreshes the device's internet-availability state every 10 seconds; Lockstep server/session checks do not alter that indicator. Each successful Google sign-in starts a fixed 30-day Lockstep session. Activity and silent Google credential renewal do not extend that deadline, and the client signs out when it is reached. A Google account may keep one web device and one extension device signed in concurrently. Signing in on another web device replaces the earlier web session; signing in on another extension device independently replaces the earlier extension session.

Recovery-key rotation generates a new random 256-bit value and re-encrypts every entry in memory; `POST /api/v1/vault/rotate` then replaces the wrapped key and every entry in one Firestore transaction (refused with 409 if any entry changed meanwhile), and only after that does the device store the result and download the new recovery key. No device can see a new key next to old ciphertext. The previous recovery key stops working. Other provisioned devices receive the new wrapped key on their next authenticated refresh and must unlock again with the synchronized passphrase. The server counts every change of the wrapped key (a vault revision); a device only uploads a key change made from the revision it last saw, so a device with a wrong clock or an old key can never overwrite a newer passphrase or rotation.

Signed-in users must configure **Lock extension after** before a master key can be created or a legacy local key can be migrated. A new or changed passphrase must contain 12–128 characters (existing shorter passphrases still unlock). The passphrase never leaves the device: Firestore stores only the lock preferences and the passkey-wrapped master key, which each client unwraps locally; IndexedDB stores the same wrapped master key. The passphrase is required to unwrap the vault before codes, recovery exports, backups, or key rotation are available. This protects copied browser storage, but cannot protect an unlocked vault from compromised JavaScript, the browser process, malware, or the operating system.

## Verify

```powershell
./mvnw.cmd test
node --check webapp/app.js
node --check webapp/crypto-store.js
node --check webapp/sw.js
node --check extension/popup.js
node --check extension/service-worker.js
```

Read [ARCHITECTURE.md](ARCHITECTURE.md) before production deployment. TOTP seeds are encrypted and codes are generated on the client. The server stores only ciphertext. Recovery keys, QR transfers, and text backups must be protected like passwords.

For the recommended Cloud Run, Firestore, Google OAuth, and Chrome Web Store production workflow, follow [DEPLOYMENT.md](DEPLOYMENT.md).

## Environment configuration

The root `.env` is the local source for backend and public browser settings. Keep it private. OAuth client IDs and API/site URLs are public identifiers; anything shipped to a browser or extension can be inspected. Never put a client secret, service-account JSON, access token or vault passphrase in a client setting. Vault keys and user tokens remain generated at runtime and do not belong in `.env`.

`./run-local.ps1` loads the file and generates both clients before starting the backend. `./configure-clients.ps1` generates the clients independently. Existing process environment variables override `.env`. For containers, pass environment variables at runtime; use a separate environment file containing only the frontend public settings for the web container. Do not give the frontend container server credentials.

`./build-firebase-hosting.ps1` also reads `.env` (explicit command-line parameters take precedence). Deploy a direct-API build using `firebase deploy --only hosting --config firebase.runtime.json`, or a Cloud Run rewrite build with `--config firebase.proxy.json`. Both generated files contain public routing/headers only. Never deploy `.env`.

Client and hosting builds read `.env` without importing its values into the terminal, so repeated builds use edits made to the file. Explicit terminal overrides still take precedence. If you previously imported old settings and want to reload the file for deployment, use:

```powershell
. ./tools/Load-Env.ps1
Import-LockstepEnv -Path ./.env -OverrideExisting
```

The explicit override replaces matching terminal variables with `.env` values. An invalid file is rejected before any terminal variables are changed. Relative file/output paths resolve against the PowerShell location, even when the .NET working directory differs.

Live shared-data refresh: current servers advertise `liveChanges` and provide an authenticated `/api/v1/events` SSE channel. Active webapp pages and extension popups fetch authoritative vault state as changes arrive, including additions, edits, deletions, passphrase/recovery-key changes and shared lock settings. Account writes commit a `changeSequence` notification marker in the same Firestore transaction; document listeners deliver changes across API instances. Notifications contain no vault data or credentials, and session credentials stay in request headers or the same-origin HttpOnly cookie. A changed key locks the receiving client and requires the current passphrase. Draft inputs remain intact unless a key/session change requires closing sensitive views; encrypted records can synchronize while editing. The 30-second timer and focus checks remain as fallback for older servers, interrupted streams and suspended clients. Reconnecting streams receive an initial invalidation to catch missed changes. Theme, pins and account order remain device-local. Deploy the backend, redeploy the webapp, and rebuild/release the extension to enable live updates on both clients.

Reconnect uploads: the webapp schedules its encrypted outbox immediately on the browser online event. An open extension popup notifies the worker to reset transient network backoff and schedule upload immediately; the worker also listens for online events and retains its retry timer/alarm for a closed popup. Browser suspension can delay background work. Explicit server Retry-After still takes precedence. Reconnect tests cover the popup open and the popup closed with a locked vault; acknowledged writes leave the queue without a reload or unlock.

Routine delta synchronization on current servers now uses `/api/v1/bootstrap` for wrapped-key metadata and ciphertext together. The server fences the response with vault revision checks, preventing a rotation between separate reads from mixing key and account versions. This replaces the separate lock-settings request during ordinary sync; older servers retain the legacy fallback. Startup still reuses its prefetched response. A changed key locks the receiving client before account decryption. Responses older than the locally known vault revision are rejected before cached lock settings or account ciphertext can be applied. If an account update and its tombstone overlap in one delta, deletion takes precedence in the API response and both client stores.

File-import cancellation: backup/QR preprocessing is tied to its originating vault view, and late recovery-file reads cannot refill a cleared form or replace a newer selection. Backup-password dialogs accept only one submission at a time; cancelled derivations cannot reset or close a later dialog. Both clients validate supported wrapping algorithms, salt size and bounded integer KDF parameters before starting derivation, including local vault records; valid encryption settings are unchanged.
