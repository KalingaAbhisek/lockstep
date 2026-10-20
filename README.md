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
5. Put that Web client ID in `extension/config.js`. Configure `apiBaseUrl` with the backend origin and `webBaseUrl` with the independently hosted PWA origin.
6. Give the API that ID as both `GOOGLE_WEB_CLIENT_ID` and `GOOGLE_EXTENSION_CLIENT_ID`.
7. If the consent screen is in **Testing**, add the Google account used for sign-in under **Test users**.

Google's stable `sub` claim—not email—is used as the database owner ID.

## Configure Firebase

1. In the [Firebase console](https://console.firebase.google.com/), create or select a project.
2. Open **Build → Firestore Database**, create the database, and choose Native mode.
3. In Google Cloud IAM, create a dedicated service account and grant only **Cloud Datastore User** (`roles/datastore.user`). For local development, create a JSON key for that account.
4. For local development, store the downloaded JSON at `secrets/firebase-service-account.json`. The directory is ignored by Git.
5. Put the Firebase project ID and portable relative path in the root `.env`:

   ```dotenv
   FIREBASE_PROJECT_ID=your-project-id
   GOOGLE_APPLICATION_CREDENTIALS=secrets/firebase-service-account.json
   ```

The service account is used only by the Spring Boot server. Never place its JSON file in the web app or extension. In production on Google Cloud, leave `GOOGLE_APPLICATION_CREDENTIALS` unset and use an attached service account instead of a long-lived JSON key.

## Run locally

The easiest backend run creates a Git-ignored `.env` for Google and Firebase configuration:

```powershell
.\run-local.ps1
```

Then add the two Google client IDs and the Firebase variables described above to `.env`, and run the same command again. The application loads `.env` automatically whether Maven starts from the repository root or the `server` directory. Operating-system environment variables and command-line arguments override `.env` values.

To configure the variables manually:

```powershell
$env:GOOGLE_WEB_CLIENT_ID = "537289145594-uf4imsthtr2ehnh0e89tsrl0s8qgu19j.apps.googleusercontent.com"
$env:GOOGLE_EXTENSION_CLIENT_ID = "537289145594-uf4imsthtr2ehnh0e89tsrl0s8qgu19j.apps.googleusercontent.com"
$env:ALLOWED_ORIGINS = "http://localhost:5173,chrome-extension://lkfonjeagenlaelocnfjlkdpflfnnojo,chrome-extension://mpifbmaidgmjddapnlfcmihdbiamkika"
$env:FIREBASE_PROJECT_ID = "your-project-id"
$env:GOOGLE_APPLICATION_CREDENTIALS = "secrets/firebase-service-account.json"
./mvnw.cmd spring-boot:run -pl server
```

In a second terminal, serve the independent frontend and open <http://localhost:5173>:

```powershell
python -m http.server 5173 --directory webapp
```

`webapp/config.js` points to `http://localhost:8080` by default. For a separate production deployment, set it to the API's HTTPS origin, or deploy the included frontend container with `LOCKSTEP_API_BASE_URL`.

When using the frontend container locally, add `LOCKSTEP_API_BASE_URL=http://localhost:8080` to the root `.env` and pass it with `docker run --env-file .env`. Cloud Run and other hosting platforms do not automatically read the local `.env`; configure the same variable on the frontend service.

Firestore creates a real document for each Google account at `users/{google-subject}` (with verified email/display metadata when supplied by Google), and stores that user's encrypted TOTP records below `users/{google-subject}/authenticatorEntries/{entry-id}`.

## Load the extension

1. Open `chrome://extensions` and enable Developer mode.
2. Choose **Load unpacked** and select the `extension` directory.
3. Add the resulting extension origin (`chrome-extension://<id>`) to `ALLOWED_ORIGINS`, comma-separated with the web origin, then restart the server.
4. Sign in from the popup. Use the scan toolbar button, drag around a TOTP QR code on the current tab, and confirm it appears in both clients.

QR recognition uses the bundled scanner and does not depend on Chrome's `BarcodeDetector`. In edit mode, the `+` button offers four additive ways to add accounts: scan a selected region of the current tab, enter a standard TOTP account manually, decode one or more local QR images, or paste one or more `otpauth://` URLs. Manual entries support 6/8 digits, SHA-1/SHA-256/SHA-512, and a configurable period. Unsupported counter-based and provider-specific formats are displayed as unavailable rather than being saved incorrectly.

The popup follows the operating system's light/dark preference and also supports an explicit theme override. Its edit mode supports renaming, deleting, and drag-reordering accounts. Pinning is a local Chrome preference, so it moves an account to the top without an API request and does not change another device's layout. The QR button intentionally reveals a scannable copy of an entry, so use it only in private and close it when finished.

Both clients support editing, device-local ordering and pinning, scannable QR transfer, and additive `.txt` backup import/export. The backup format contains one standard `otpauth://totp/...` URI per line. Importing adds entries and never deletes or replaces existing entries; duplicate URIs are therefore imported as separate entries. Exported files contain usable TOTP secrets and must be protected like passwords.

The web app uses the camera scanner on mobile devices. On laptops and desktop computers, the same action opens the browser's screen-sharing picker; the user drags around a QR code in the local preview before it is decoded.

TOTP seeds are encrypted with a per-user AES-256-GCM key before they leave the browser. Firestore receives only ciphertext, a random IV, a key version, and display/TOTP metadata; code generation, QR generation, and backup export happen locally. Use **Download recovery key** after adding the first account and store the file offline. Another device cannot decrypt synchronized entries until that recovery key is imported. If you forget the Lockstep passkey, use **Forgot passkey?** and the current recovery key to create a new passkey.

IndexedDB stores only an AES-256-GCM-wrapped vault master key. A local wrapping key is derived from the Lockstep passkey with PBKDF2-HMAC-SHA-256 using a random 128-bit salt and 600,000 iterations; the unwrapped master key exists only in client memory while the vault is unlocked. Locking, signing out, closing/restarting the client, or making the PWA inactive clears that in-memory key. A key version is merely public derivation context and is safe to expose, but possession of the master/recovery key permits derivation of every version and therefore compromises the entire vault.

The PWA and extension retain an encrypted IndexedDB replica. Accounts added or edited without connectivity are usable immediately and an idempotent UUIDv4 operation is placed in the local outbox. Startup, refresh, focus, and reconnection attempt to upload pending operations. A queue item is removed only after the API acknowledges it, while the encrypted local entry remains available for offline code generation.

The Online/Offline indicator refreshes the device's internet-availability state every 10 seconds; Lockstep server/session checks do not alter that indicator. A Google account may keep one web device and one extension device signed in concurrently. Signing in on another web device replaces the earlier web session; signing in on another extension device independently replaces the earlier extension session.

Key rotation generates a new random 256-bit vault master key, re-encrypts every entry locally, publishes the new wrapped key before the replacement ciphertext, and downloads a new recovery key. The previous recovery key stops working. Other provisioned devices receive the new wrapped key on their next authenticated refresh and must unlock again with the synchronized passkey.

Signed-in users must configure **Lock extension after** before a master key can be created or a legacy local key can be migrated. The passkey must contain 4–128 characters. Firestore stores only a separate random salt and PBKDF2-HMAC-SHA256 verifier; IndexedDB stores the independently salted wrapped master key. The passkey is required to unwrap the vault before codes, recovery exports, backups, or key rotation are available. This protects copied browser storage, but cannot protect an unlocked vault from compromised JavaScript, the browser process, malware, or the operating system.

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
