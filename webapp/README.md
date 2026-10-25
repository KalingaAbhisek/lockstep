# Lockstep web app

This directory is a standalone static Progressive Web App. It is not packaged in the Spring Boot API JAR.

## Configuration

Set `LOCKSTEP_API_BASE_URL`, `LOCKSTEP_WEB_BASE_URL` and `GOOGLE_WEB_CLIENT_ID` in the repository root `.env`, then run `./configure-clients.ps1` from the root. It generates the Git-ignored `webapp/config.js` and the extension configuration together. Do not edit generated files. For Firebase Hosting, `./build-firebase-hosting.ps1` reads these settings directly. Add the frontend's exact origin to the backend `ALLOWED_ORIGINS` and Google OAuth authorized JavaScript origins. Browser configuration is public; never include service-account keys or client secrets.

The production container exposes the PWA only below `/lockstep/`. Its assets, manifest, privacy page, and service worker resolve within that base path. The included Nginx configuration redirects `/lockstep` to `/lockstep/`, serves the application there, and returns a blank `404 Not Found` page for `/` and every other path. Configure an upstream reverse proxy to route `https://kalin.ga/lockstep` and its descendants to this frontend service.

## Local hosting

Build and run the same Nginx container used in production, then open `http://localhost:5173/lockstep/`:

```powershell
docker build -t lockstep-webapp webapp
docker run --rm -p 5173:8080 -e LOCKSTEP_API_BASE_URL=http://host.docker.internal:8080 lockstep-webapp
```

The container returns a blank page at `http://localhost:5173/` and for every path outside `/lockstep/`.

Start the API separately with `./run-local.ps1`.

## Container deployment

Build from the repository root using the `webapp` directory as the Docker context:

```powershell
docker build -t lockstep-webapp webapp
docker run --rm -p 5173:8080 --env-file .env.frontend lockstep-webapp
```

Create an ignored `.env.frontend` with only the public frontend settings copied from the root `.env`: `LOCKSTEP_API_BASE_URL`, `GOOGLE_WEB_CLIENT_ID` and `LOCKSTEP_USE_API_PROXY`. Never pass server credentials to the frontend container. Alternatively, pass these public variables with Docker `-e` options.

Set `LOCKSTEP_API_BASE_URL` to the production API origin when deploying the container. The container checks its settings when it starts and stops with a message if one is malformed: the API address must be an `https://` address (plain `http://` only for `localhost`, `127.0.0.1` and `host.docker.internal`), and the Google client ID may contain only letters, digits, `.`, `_` and `-`. Set `GOOGLE_WEB_CLIENT_ID` (or the container override `LOCKSTEP_GOOGLE_CLIENT_ID`) to the Web OAuth client ID; the page then reads it from `config.js` instead of requesting `/api/v1/config` on startup (without it, the page requests it once and refreshes its saved copy at most once a day). The startup script renders `config.js`; the frontend image does not need to be rebuilt when only the API origin changes. It also configures Nginx to listen on the platform-provided `PORT`, defaulting to `8080` for local containers and Cloud Run.

## Same-origin API proxy and HttpOnly session cookie

With `LOCKSTEP_USE_API_PROXY=true` the container also serves `/lockstep/api/*` by forwarding to `LOCKSTEP_API_BASE_URL`, and writes `config.js` so the app calls the API on its own origin. The API then sets the 30-day session as an HttpOnly, Secure, `SameSite=Strict` cookie (path `/lockstep/api`) instead of returning a token for `localStorage`. Requests still require the `X-Lockstep-Client` header, which cross-site forms cannot send. Without the variable the app calls the API origin directly, as before. Firebase Hosting can do the same with a rewrite (see `DEPLOYMENT.md`, "Cookie session with Firebase Hosting").

## Minified scripts

The container image serves `app.js`, `crypto-store.js` and `sw.js` minified with uglify-js (top-level names are
kept, so behaviour is identical). The Firebase Hosting build does the same when Node.js is installed. To test the
exact files, build them with `docker build --target minified-files --output type=local,dest=<dir> webapp`, copy
them over a copy of `webapp/`, and run `tests/e2e` with `WEBAPP_DIR=<that copy>`.

Client generation and the Firebase Hosting build read `.env` without adding values to the terminal environment. Explicit environment variables still override the file. If a deployment terminal already contains older imported values, reload using `Import-LockstepEnv -Path ./.env -OverrideExisting` after dot-sourcing `./tools/Load-Env.ps1`.

Live shared-data refresh: current servers advertise `liveChanges` and provide an authenticated `/api/v1/events` SSE channel. Active webapp pages and extension popups fetch authoritative vault state as changes arrive, including additions, edits, deletions, passphrase/recovery-key changes and shared lock settings. Account writes commit a `changeSequence` notification marker in the same Firestore transaction; document listeners deliver changes across API instances. Notifications contain no vault data or credentials, and session credentials stay in request headers or the same-origin HttpOnly cookie. A changed key locks the receiving client and requires the current passphrase. Draft inputs remain intact unless a key/session change requires closing sensitive views; encrypted records can synchronize while editing. The 30-second timer and focus checks remain as fallback for older servers, interrupted streams and suspended clients. Reconnecting streams receive an initial invalidation to catch missed changes. Theme, pins and account order remain device-local. Deploy the backend, redeploy the webapp, and rebuild/release the extension to enable live updates on both clients.

Routine delta synchronization on current servers now uses `/api/v1/bootstrap` for wrapped-key metadata and ciphertext together. The server fences the response with vault revision checks, preventing a rotation between separate reads from mixing key and account versions. This replaces the separate lock-settings request during ordinary sync; older servers retain the legacy fallback. Startup still reuses its prefetched response. A changed key locks the receiving client before account decryption. Responses older than the locally known vault revision are rejected before cached lock settings or account ciphertext can be applied. If an account update and its tombstone overlap in one delta, deletion takes precedence in the API response and both client stores.

File-import cancellation: backup/QR preprocessing is tied to its originating vault view, and late recovery-file reads cannot refill a cleared form or replace a newer selection. Backup-password dialogs accept only one submission at a time; cancelled derivations cannot reset or close a later dialog. Both clients validate supported wrapping algorithms, salt size and bounded integer KDF parameters before starting derivation, including local vault records; valid encryption settings are unchanged.
