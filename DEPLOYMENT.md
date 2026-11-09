# Lockstep production deployment

## Recommended topology

Deploy the Spring Boot API and static PWA independently. The examples below use two public **Google Cloud Run** services, although `webapp/` can instead be hosted by any HTTPS static host. Use **Firestore in Native mode** in the same Google Cloud project and distribute the Manifest V3 extension through the **Chrome Web Store**.

The backend image contains only the API. The PWA image is built from `webapp/` and receives the API origin through `LOCKSTEP_API_BASE_URL` at container startup.

Use one Google Cloud project for Cloud Run, Firestore, and OAuth. The examples below use PowerShell and these placeholders:

```powershell
$ProjectId = "YOUR_GOOGLE_CLOUD_PROJECT_ID"
$Region = "us-east1"
$ApiService = "lockstep-api"
$WebService = "lockstep-web"
$RuntimeServiceAccount = "lockstep-runtime@$ProjectId.iam.gserviceaccount.com"
$GoogleClientId = "YOUR_WEB_OAUTH_CLIENT_ID.apps.googleusercontent.com"
```

### Configure the local source values

Copy `.env.example` to `.env` if you have not already done so. Keep your existing `.env` when updating. Set `GOOGLE_WEB_CLIENT_ID`, `GOOGLE_EXTENSION_CLIENT_ID`, `FIREBASE_PROJECT_ID`, `ALLOWED_ORIGINS`, `LOCKSTEP_API_BASE_URL` and `LOCKSTEP_WEB_BASE_URL` for the target deployment. Both Google IDs use the Web OAuth client for this implementation. The web base URL includes `/lockstep`; CORS origins do not include paths.

Run `./configure-clients.ps1` after changing these settings and before loading or packaging the extension. This generates ignored `webapp/config.js`, `extension/config.js` and `extension/manifest.json`. Store extension version, icons and permissions metadata in `extension/manifest.template.json`. Existing process variables override `.env`; explicit hosting-build parameters override both.

Cloud Run deployment commands below remain valid and pass configuration explicitly. Cloud Run does not upload or automatically load your local `.env`; set server and frontend variables on their respective services. Never pass a complete backend environment file to the frontend. Production API credentials come from the attached service account, not a bundled key file.

This deployment uses the Cloud Run region `us-east1`. Choose the corresponding Firestore location carefully because a Firestore database location cannot be changed after creation.

## 1. Production prerequisites

Install the Google Cloud CLI, sign in, and select the project:

```powershell
gcloud auth login
gcloud config set project $ProjectId
gcloud config set run/region $Region
```

Enable billing for the project in Google Cloud Console. Then enable the required APIs:

```powershell
gcloud services enable run.googleapis.com cloudbuild.googleapis.com artifactregistry.googleapis.com firestore.googleapis.com iam.googleapis.com
```

Run the repository checks before every release:

```powershell
.\mvnw.cmd test
node --check webapp/app.js
node --check webapp/crypto-store.js
node --check webapp/sw.js
node --check extension/popup.js
node --check extension/service-worker.js
```

Do not deploy `.env`, anything under `secrets/`, a Firebase JSON key, recovery keys, exported OTP backups, or development logs.

The commands in this guide perform manual deployments. Connecting a GitHub repository through Cloud Run can create Cloud Build triggers that deploy every push. To retain manual releases, open **Cloud Build → Triggers**, check both the configured region and `global`, and disable the API and frontend repository triggers. Disabling a trigger does not stop or delete the running Cloud Run service.

## 2. Create Firestore and the Cloud Run identity

In Firebase Console, open **Build → Firestore Database**, create a **Native mode** database, and select the intended production location. Do not choose a temporary/test database for production.

Create a dedicated Cloud Run runtime identity and give it only Firestore data access:

```powershell
gcloud iam service-accounts create lockstep-runtime --display-name="Lockstep Cloud Run runtime"
gcloud projects add-iam-policy-binding $ProjectId `
  --member="serviceAccount:$RuntimeServiceAccount" `
  --role="roles/datastore.user"
```

Production Cloud Run uses Application Default Credentials from this attached service account. Do **not** set `GOOGLE_APPLICATION_CREDENTIALS` and do not upload a service-account key.

## 3. Configure Google OAuth

In **Google Cloud Console → Google Auth Platform**:

1. Configure Branding, Audience, and Data Access.
2. Use only the OpenID scopes the application needs: `openid`, `email`, and `profile`.
3. Add test users while the app is in Testing, or complete the production publishing requirements before public use.
4. Create an OAuth client with application type **Web application**.
5. Save its client ID in `$GoogleClientId`.

The production frontend URL and Chrome Web Store extension ID are added to this client later. Do not create a client secret for either browser client, and never put a client secret in the PWA or extension.

For a public OAuth app, host a public home page, privacy policy, and terms page on a domain you control. The privacy policy must accurately describe Google profile data, encrypted authenticator metadata/ciphertext, QR capture behavior, retention/deletion, and all processors used.

## 4. Deploy the backend API

The root `Dockerfile` builds only the Spring Boot API. The first deployment establishes its URL; the temporary localhost CORS origin is replaced after the frontend is deployed:

```powershell
gcloud run deploy $ApiService `
  --source . `
  --allow-unauthenticated `
  --service-account $RuntimeServiceAccount `
  --set-env-vars="GOOGLE_WEB_CLIENT_ID=$GoogleClientId,GOOGLE_EXTENSION_CLIENT_ID=$GoogleClientId,FIREBASE_PROJECT_ID=$ProjectId,ALLOWED_ORIGINS=http://localhost:5173" `
  --min-instances=1 `
  --cpu-boost `
  --max=10 `
  --memory=512Mi `
  --cpu=1
```

The API image records a class-data-sharing archive during `docker build` (a short trial start that never connects to Firestore), which makes each new instance start faster. `--min-instances=1` keeps one API instance running so users never wait for a Java cold start, and `--cpu-boost` gives new instances extra CPU while they start. Keeping one instance warm costs a few dollars a month.

The API remembers a validated client session in memory for `SESSION_CACHE_SECONDS` (default `5`) so most requests skip one Firestore read. Key changes, vault reset and "sign out of all devices" always read the stored session. A login on another device is still detected immediately on the same instance; when several instances are running, a replaced session can keep working for up to that many seconds on another instance. Set `SESSION_CACHE_SECONDS=0` to check Firestore on every request.

Read the assigned API URL:

```powershell
$ApiOrigin = gcloud run services describe $ApiService --format="value(status.url)"
$ApiOrigin
```

## 5. Deploy the frontend PWA

The `webapp/Dockerfile` serves only the static PWA and renders `config.js` from the API URL at startup:

```powershell
gcloud run deploy $WebService `
  --source webapp `
  --allow-unauthenticated `
  --set-env-vars="LOCKSTEP_API_BASE_URL=$ApiOrigin,LOCKSTEP_GOOGLE_CLIENT_ID=$GoogleClientId" `
  --min-instances=1 `
  --max=10 `
  --memory=256Mi `
  --cpu=1

$WebOrigin = gcloud run services describe $WebService --format="value(status.url)"
$WebOrigin
```

In the Web OAuth client, add `$WebOrigin` exactly under **Authorized JavaScript origins**. Do not add a trailing slash or path. It will look similar to:

```text
https://lockstep-xxxxxxxxxx-xx.a.run.app
```

Update API CORS with the production frontend origin:

```powershell
gcloud run services update $ApiService `
  --update-env-vars="GOOGLE_WEB_CLIENT_ID=$GoogleClientId,GOOGLE_EXTENSION_CLIENT_ID=$GoogleClientId,FIREBASE_PROJECT_ID=$ProjectId,ALLOWED_ORIGINS=$WebOrigin"
```

Open `$WebOrigin`, sign in, configure lock protection, add a disposable test account, refresh, sign out/in, unlock, and verify the account remains available. Also install the PWA once on a phone and test offline code display.

The frontend sends a `Content-Security-Policy` and `Strict-Transport-Security` header (see `webapp/nginx.conf` and `firebase.json`). The policy allows only the app itself, the API origin in `LOCKSTEP_API_BASE_URL`, and Google's sign-in. After deploying, sign out and sign in once to confirm the Google button still works; the browser console reports anything the policy blocks.

### Optional: serve the PWA from Firebase Hosting

Firebase Hosting can replace the Nginx Cloud Run service for the static files. It serves them from a global CDN with gzip/Brotli compression and has no cold starts. The repository includes `firebase.json` and a build script that publishes the app below `/lockstep/` with the same headers and caching rules as `webapp/nginx.conf`:

```powershell
npm install -g firebase-tools
firebase login
firebase use $ProjectId
.\build-firebase-hosting.ps1 -ApiBaseUrl $ApiOrigin -GoogleClientId $GoogleClientId
firebase deploy --only hosting --config firebase.runtime.json
```

Then point the `/lockstep` and `/lockstep/*` routes of your path-aware reverse proxy (or the custom domain) at the Firebase Hosting site instead of the Cloud Run frontend service, and add the Hosting origin to `ALLOWED_ORIGINS` and the OAuth client if users will open it directly.

### Optional custom domains

A custom HTTPS domain is preferable for a public product and is required for a polished OAuth home/privacy presence. Use separate web and API hostnames, such as `app.example.com` and `api.example.com`. After they work:

1. Add its exact origin to the OAuth client's Authorized JavaScript origins.
2. Set `$WebOrigin` and `$ApiOrigin` to their custom origins.
3. Redeploy the frontend with `LOCKSTEP_API_BASE_URL=$ApiOrigin`.
4. Update API `ALLOWED_ORIGINS` as shown below.
5. Use the API origin for extension API access and the web origin for its privacy-policy link.

The frontend is published below `https://kalin.ga/lockstep/` through a path-aware reverse proxy. Route `/lockstep` and `/lockstep/*` to the frontend service. The included Nginx configuration returns blank `404 Not Found` pages for the domain root and all other paths outside `/lockstep/`, so the app is never exposed at `/`. For OAuth and API CORS, the web origin remains `https://kalin.ga`; paths are never included in an origin value. The extension `webBaseUrl` may include the full `https://kalin.ga/lockstep` base URL so its privacy link opens the correct page.

## 6. Obtain the permanent Chrome extension ID

The published extension ID must be known before the final OAuth and CORS settings can be completed.

1. Register a Chrome Web Store developer account and complete its publisher profile.
2. Configure the production API/site URLs in `.env`, generate the extension files, and make an initial ZIP whose root contains `manifest.json` (not an outer `extension` folder):

   ```powershell
   .\configure-clients.ps1
   New-Item -ItemType Directory -Force dist | Out-Null
   Get-ChildItem extension -Exclude manifest.template.json |
     Compress-Archive -DestinationPath dist\lockstep-extension-draft.zip -Force
   ```

3. In the Chrome Developer Dashboard choose **Add new item** and upload the draft ZIP.
4. Do not submit it yet. Copy the permanent item/extension ID shown by the dashboard.

Review the included extension icons and prepare the screenshots and promotional assets requested by the Store dashboard. Declare any icon changes in `extension/manifest.template.json`, then regenerate the manifest.

## 7. Connect the production extension

Set each development or Chrome Web Store ID and build its origin locally. For one extension:

```powershell
$ExtensionId = "YOUR_CHROME_WEB_STORE_EXTENSION_ID"
$ExtensionOrigins = "chrome-extension://$ExtensionId"
```

When both unpacked and Store builds must work, include both IDs:

```powershell
$ExtensionIds = @("YOUR_DEVELOPMENT_EXTENSION_ID", "YOUR_CHROME_WEB_STORE_EXTENSION_ID")
$ExtensionOrigins = ($ExtensionIds | ForEach-Object { "chrome-extension://$_" }) -join ","
```

In the same Web OAuth client, add this exact **Authorized redirect URI**:

```text
https://YOUR_CHROME_WEB_STORE_EXTENSION_ID.chromiumapp.org/google
```

There is no trailing slash. The path `/google` is required by the implementation. Register one redirect URI for every extension ID that can sign in.

Update the deployment values in the root `.env`:

```dotenv
LOCKSTEP_API_BASE_URL=https://YOUR_API_HOST
LOCKSTEP_WEB_BASE_URL=https://YOUR_WEBAPP_HOST/lockstep
GOOGLE_WEB_CLIENT_ID=YOUR_WEB_OAUTH_CLIENT_ID.apps.googleusercontent.com
GOOGLE_EXTENSION_CLIENT_ID=YOUR_WEB_OAUTH_CLIENT_ID.apps.googleusercontent.com
```

Then regenerate both clients:

```powershell
.\configure-clients.ps1
```

The generator sets the extension's host permissions and `connect-src` to the configured API origin automatically. Do not edit `extension/config.js` or `extension/manifest.json` directly; regeneration replaces them. Change manifest metadata in `extension/manifest.template.json`.

Update Cloud Run CORS so it contains the exact PWA and extension origins:

```powershell
$AllowedOrigins = "$WebOrigin,$ExtensionOrigins"
gcloud run services update $ApiService `
  --region $Region `
  --update-env-vars="^@^ALLOWED_ORIGINS=$AllowedOrigins"
```

The custom `@` delimiter is required because `ALLOWED_ORIGINS` is itself a comma-separated value. Each web entry must be an origin only, such as `https://app.example.com`; do not include a path such as `/lockstep`.

Keep `GOOGLE_WEB_CLIENT_ID` and `GOOGLE_EXTENSION_CLIENT_ID` set to the Web OAuth client ID used by the two clients. Cloud Run creates a new revision when the environment changes.

## 8. Test the store build locally

Increment `version` in `extension/manifest.template.json` for every uploaded release, then run `./configure-clients.ps1`. Load the production-configured `extension` directory through `chrome://extensions` and test:

- Google sign-in and sign-out.
- First-time lock-protection setup and unlock after closing/reopening the popup.
- Add, edit, delete, pin, reorder, import, export, QR display, local QR image import, and visible-tab QR capture.
- Offline behavior followed by reconnection and synchronization.
- Web-to-extension and extension-to-web encrypted synchronization.
- Expired-session behavior, recovery-key restore, forgot-passkey flow, and key rotation.
- No requests to `localhost`, no browser-console errors, and no secrets in the ZIP.

An unpacked extension normally has a different ID from the Web Store item. The OAuth redirect for the final store ID therefore cannot be completely validated with an arbitrary unpacked ID. Keep a separate authorized redirect for a development ID if local testing is required, then remove unused development origins before launch.

Build the final archive:

```powershell
.\configure-clients.ps1
New-Item -ItemType Directory -Force dist | Out-Null
$Version = (Get-Content extension\manifest.json | ConvertFrom-Json).version
Get-ChildItem extension -Exclude manifest.template.json |
  Compress-Archive -DestinationPath "dist\lockstep-extension-$Version.zip" -Force
```

Inspect the ZIP and verify that `manifest.json` is at its root.

## 9. Complete the Chrome Web Store listing

In the item dashboard complete:

1. **Store listing:** clear single-purpose description, icon, screenshots, support URL, home page, and category.
2. **Privacy:** link the public privacy policy and truthfully disclose authentication information, name/email/profile data, user-provided OTP account metadata, encrypted synchronized records, and website content accessed only when the user explicitly starts QR capture.
3. **Permission justifications:**
   - `activeTab` and `scripting`: capture/decode only the currently visible tab after the user starts QR capture.
   - `identity`: open the Google OAuth sign-in flow.
   - `storage`: retain encrypted local vault data and device-local preferences.
   - `alarms`: perform scheduled background maintenance/refresh used by the extension.
   - `idle`: detect a locked or idle device locally so Lockstep can lock the vault when the user enables screen-lock protection; the state is not transmitted.
   - production host permission: call only the Lockstep API.
4. **Limited Use:** make the required certification and put the Chrome Web Store Limited Use statement in the public privacy policy.
5. **Distribution:** start with Trusted testers or Unlisted for final production verification, then move to Public when ready.

Use this single-purpose statement in the dashboard:

> Lockstep is an authenticator that stores and generates TOTP verification codes locally, synchronizes encrypted authenticator records across the user's Lockstep clients, and lets the user add an account by explicitly scanning a QR code from the visible tab.

In **Data usage**, disclose these handled data categories:

- **Personally identifiable information:** Google account identifier, email address, and display name, used for sign-in and to associate the user with their synchronized vault.
- **Authentication information:** user-provided authenticator account metadata and encrypted TOTP secrets, used only to provide the authenticator vault and encrypted synchronization.
- **Website content:** the visible tab image accessed only after the user starts QR scanning. It is decoded locally, is not retained, and is not transmitted to Lockstep or its service providers.

Certify that this data is used only for Lockstep's disclosed single purpose and related security or reliability needs; is not sold; is not used for advertising, profiling, lending, or credit decisions; and is not made available for humans to read except where the Chrome Web Store Limited Use policy permits. The dashboard disclosures, listing description, extension behavior, and public privacy policy must remain consistent.

Use the public privacy-policy URL `https://kalin.ga/lockstep/privacy.html` only after it resolves over HTTPS without authentication. Enter a monitored public support address in the dashboard and publish the same address in the policy's Contact section before submission.

Upload the final ZIP, submit it for review, and wait for approval. A new upload must have a higher manifest version.

## 9a. Data protection, cleanup and abuse limits

Run these once per project (PowerShell, same placeholders as above).

**Deny direct Firestore access.** Only the API (Admin SDK) uses Firestore, so the security rules deny everything. Check **Firestore → Rules** in the Firebase console, or deploy the tracked file:

```powershell
firebase deploy --only firestore:rules
```

**Index only what is queried.** Firestore indexes every field by default; Lockstep only queries `updatedAt` (entries) and `deletedAt` (deletion records). `firestore.indexes.json` exempts every other field, so each write updates fewer index entries (faster, cheaper, and recovery-key rotations stay well inside Firestore's 10 MiB transaction limit). It disables the previous TTL on `deletedEntries.expireAt`:

```powershell
firebase deploy --only firestore:indexes
```

**Backups.** Turn on point-in-time recovery (7 days) and a daily backup kept for 14 days:

```powershell
gcloud firestore databases update --database="(default)" --enable-pitr
gcloud firestore backups schedules create --database="(default)" --recurrence=daily --retention=14d
```

**Retain deletion records.** Deleting an account permanently reserves its UUID in a small `deletedEntries` record. This prevents an offline retry of its original create request from resurrecting it. Records are removed by a full vault reset; re-adding an authenticator uses a fresh UUID. Before deploying this server against an existing database, disable any old TTL policy (or deploy the indexes above and verify it is disabled):

```powershell
gcloud firestore fields ttls update expireAt --collection-group=deletedEntries --disable-ttl
```

**Abuse limits.** The API rejects request bodies over 1 MiB (6 MiB for a recovery-key rotation, which re-uploads every account), secrets over 1 KiB and encrypted names over 2 KiB per account, limits each account to 120 changes, 300 reads and 10 sign-ins per minute (per instance), and allows at most 1,000 accounts per user. HEAD requests count as reads. A backup file may be at most 8 MB and a recovery-key file 16 KB (checked in the apps before reading). A Firestore call that takes longer than 30 seconds is cancelled and answered with `503` (the apps keep their local copy and retry).

Requests with a made-up session cannot run up Firestore reads: a session token that is not in the format the API issues is refused without any lookup, a wrong account-and-token pair is remembered for a minute (repeating it costs nothing), and each client address gets at most 30 session lookups per minute that turn out wrong (lookups still in progress count too, so a burst of simultaneous requests cannot slip through); after that its uncached requests get `429` without a lookup, while sessions already in the server's short cache keep working. The address is the one Cloud Run's front end adds to `X-Forwarded-For` (the API uses `server.forward-headers-strategy: native`, so a caller cannot choose it). If you put a load balancer or another proxy in front of the API, list its addresses as a regular expression in `TRUSTED_PROXIES` on the API service (for a Google load balancer, its own external IP address, for example `TRUSTED_PROXIES=203\.0\.113\.10`); otherwise every request appears to come from the proxy. Web app requests forwarded by the nginx proxy (`LOCKSTEP_USE_API_PROXY=true`) share the frontend's address in the same way.

Because all these counters are per instance, put a load balancer with a Cloud Armor rate-limiting rule in front of Cloud Run for a shared limit, and restrict the service so the `run.app` address cannot bypass it:

```powershell
gcloud run services update $ApiService --region $Region --ingress=internal-and-cloud-load-balancing
```

Add a billing budget with alerts (Billing → Budgets & alerts) and Cloud Monitoring alerts on the API's 5xx responses, p95 latency and 429 responses (a spike means someone is hitting the rate limits).

Deletion records already removed by the old TTL cannot be reconstructed. For development environments, start with a fresh test vault if protection against every historical retry is required. No data is erased automatically by this update.

**Confirmation with Google for destructive actions.** Removing an authenticator, resetting the vault, rotating the recovery key, replacing the passphrase key and "Sign out of all devices" need a Google token issued in the last `REAUTH_MAX_AGE_SECONDS` (default `300`); the apps ask the user to confirm with Google when theirs is older. A copied 30-day Lockstep session alone cannot do these. Individual deletion and vault reset also verify the existing vault passphrase locally; it is never sent to the server. This uses the existing confirmation flow and does not enroll WebAuthn credentials. It does not give the server independent proof of passphrase knowledge or a forced Google Account reauthentication. Deletion requires connectivity and retains the local account until the server acknowledges it.

A reset first marks the account "reset in progress" (sign-in and passphrase setup wait with a "try again in a minute" message), deletes the sessions, then the vault; an interrupted reset is finished by the next sign-in. Every cleanup batch checks its lease and deletes documents in the same transaction, so a stale worker cannot delete a newly initialized vault. Recovery-key rotations have no separate cooldown or failed-attempt waiting period: another device can rotate immediately after adopting the current key and verifying the passphrase. Each attempt charges the per-account 1,200-operation budget by the greater of the submitted and stored account counts (at least one, or conservatively 1,000 when an older vault has no stored count). Revision/reset checks run before reading entries, and concurrent stale rotations are refused without overwriting changes. Failed rotations retain their operation charge. General request and operation limits still apply and are per instance, so retain the shared infrastructure limits above.

Reset increments a separate `vaultGeneration`. Session creation reads reset state and captures that generation in the same Firestore transaction as the session write. The API binds the verified session generation to entry, key, rotation and reset mutations; it is never taken from a client header. Transactions refuse an older generation even after a new vault is initialized. An expired cleanup lease still blocks ordinary setup and sign-in until cleanup is completed. Existing records without a generation start at zero and need no data deletion.

Both clients upgrade IndexedDB to version 3 without deleting vault records. Reload older open web tabs and the extension after updating; this prevents an older client from continuing to write through its previous database connection. Rotation holds a cross-tab Web Lock through preparation, the API request and local commit. Other mutations retain their form inputs and report that rotation is running. Local sync application checks a persisted generation so delayed replies cannot restore removed accounts. Uploads use persisted sequences and mutation dependencies rather than wall-clock ordering, including existing queued records. The existing passphrase and Google confirmation flows are unchanged.

Startup checks the vault revision before and after reading entries, retrying if rotation or reset crossed the reads. Key-save acknowledgements update only the exact wrapper returned by the server and cannot lower a stored revision. Client sync validates IDs before queuing writes and aborts its transaction on application errors. Reduced-motion expiry bars update in discrete steps.

Sign-out compares the requesting session's token hash transactionally before deleting sessions; signing out everywhere deletes both client records in that same transaction. A delayed sign-out cannot delete a newer session; a stale sign-out-everywhere request returns 409 SESSION_CHANGED instead of claiming success. Sign-out responses deliberately do not expire the HttpOnly cookie, because a late response could otherwise erase a newer sign-in's cookie. The revoked cookie is unusable and is replaced on the next sign-in or expires normally.

Vault reads also reserve a shared per-account budget in Firestore (`users/<subject>/readBudgets/vault`) before querying entries. Each 60-second window permits 20,000 query-document units and eight complete snapshots across all API instances. A full query reserves 1,001 units and refuses an over-limit collection without returning a partial vault. Delta queries reserve 50-document pages; deltas reaching 1,000 records fall back to a complete snapshot. Budget metadata contains counters only, uses no indexes, and cannot refill merely because one instance's clock is behind. Existing infrastructure request limits remain useful against many-account abuse.

Recovery-key import carries the lock generation through verification, wrapping and a tracked IndexedDB transaction, so locking or signing out cancels the pending restore. Authentication responses are bound to the initiating account/session; web sign-ins also have a local nonce for HttpOnly-cookie sessions, and extension credential writes and cleanup are serialized. Expired codes regenerate before copying. Extension QR imports are limited to 20 MB and 40 megapixels and decoded at a maximum dimension of 1,600 pixels; bitmaps are always closed.

**Key-protection switches (both on by default):**

- `ARGON2ID_WRAPPING` (default `true`) — new and changed passphrases, and existing vaults at their next unlock, are protected with Argon2id (64 MiB, 3 passes) instead of PBKDF2. Extension versions from before Argon2id support cannot open such a vault, so publish the extension from this repository (not an older build). Setting it to `false` only stops new keys from using Argon2id; keys already protected with it keep working.
- `REQUIRE_EDIT_BASE` (default `true`) — a change to an existing account must say which version it was made from, so a delayed or outdated upload can never overwrite a newer edit. Apps from before this release get a refusal they already understand: they drop that one change and show "Lockstep is out of date"; after updating, the user makes the change again. Set it to `false` only while such apps are still widely used.
- `REQUIRE_VAULT_REVISION` (default `true`) — key changes that do not say which vault revision they expect are refused, so an outdated app can never replace a newer passphrase. The web app updates itself on the next visit; a browser tab left open from before this release gets a "Lockstep is out of date" message when it changes the passphrase and works again after a reload.

If an older extension build is ever in use, turn both off until it is updated:

```powershell
gcloud run services update $ApiService --region $Region --update-env-vars="ARGON2ID_WRAPPING=false,REQUIRE_VAULT_REVISION=false"
```

**Trusted Types and security-policy reports.** The extension enforces Trusted Types. The web app sends them as `Content-Security-Policy-Report-Only`, because Google's sign-in script cannot be tested outside production. Both web policies report violations to the API (`POST /api/v1/csp-report`, public, at most 20 reports per minute per address, never touches Firestore), which logs one line per report. A week or so after deploying, look for them:

```powershell
gcloud logging read 'resource.type="cloud_run_revision" AND resource.labels.service_name="'$ApiService'" AND textPayload:"Content-Security-Policy report"' --limit 50 --freshness 7d
```

If no `require-trusted-types-for` reports appear (and signing in works in your own browser with the console open), move `require-trusted-types-for 'script'` from the report-only header into the main `Content-Security-Policy` in `webapp/nginx.conf` (and `firebase.json`). The hosting build generates API-specific CSP and reporting URLs in `firebase.runtime.json` for direct API builds. Same-origin rewrite builds use `firebase.proxy.json`. Rebuild after changing the API address; do not hand-edit generated headers.

**Exports.** Downloading a backup or the recovery key asks for the vault passphrase again (checked on the device), and a backup can be encrypted with its own password (Argon2id + AES-256-GCM, a `.json` file that either app imports with that password). The plain-text `otpauth://` backup stays available for moving to other authenticator apps.

**API memory.** The API image runs Java with `-XX:+UseSerialGC -XX:MaxRAMPercentage=75`, so the heap can use three quarters of the instance's memory. If you set `JAVA_OPTS` on the service yourself, keep `-XX:MaxRAMPercentage=75` in it.

**Health check.** `GET /actuator/health` answers `{"status":"UP"}` once the API has started (it never touches Firestore). Use it as the startup and liveness probe:

```powershell
gcloud run services update $ApiService --region $Region `
  --startup-probe="httpGet.path=/actuator/health,initialDelaySeconds=0,periodSeconds=2,failureThreshold=30,timeoutSeconds=2" `
  --liveness-probe="httpGet.path=/actuator/health,periodSeconds=30,failureThreshold=3,timeoutSeconds=2"
```

**Dedicated identity for the frontend.** The nginx frontend only serves files and forwards API requests, so give it its own service account with no roles instead of the default compute account (which can edit the project):

```powershell
gcloud iam service-accounts create lockstep-web --display-name="Lockstep web frontend (no roles)"
gcloud run services update $WebService --region $Region --service-account "lockstep-web@$ProjectId.iam.gserviceaccount.com"
```

**Repository security.** In GitHub → Settings → Code security, turn on secret scanning with push protection, Dependabot alerts and **private vulnerability reporting** (`SECURITY.md` points reporters there). In Settings → Branches, protect `main`: require a pull request with review from code owners (`.github/CODEOWNERS`) and the CI checks (API tests, Firestore emulator, web app and extension checks, secret scan, container image scan, CodeQL). The CI workflows add CodeQL, dependency review on pull requests, a Gitleaks secret scan of the whole history, a scan of both container images (failing on fixable critical or high findings, with full reports on the Security → Code scanning page) and a check of every vendored library against `tools/vendor/manifest.json`. Code scanning (CodeQL, the image-scan reports on the Security page) and dependency review need GitHub Code Security on a private repository, which a personal account cannot enable: while the repository is private the workflows skip them instead of failing (the image checks that fail on critical or high findings still run); making the repository public turns them on with no other change. The API image removes the Ubuntu base's unused Pebble binary, whose Go runtime otherwise fails the image scan. Both images also install their distribution's published security updates when they are built (`apt-get upgrade` in the API image, `apk upgrade` in the web image), so a fix released after the base image was published does not fail the scan; `server/pom.xml` pins Guava (which Firestore brings in) to a fixed release for the same reason. The browser tests need a Playwright release that supports the CI runner's Ubuntu version: when `ubuntu-latest` moves to a new Ubuntu release, update Playwright in `tests/e2e` (Dependabot proposes it). Dependabot proposes base-image updates; to pin an image to an exact digest, read it with `docker buildx imagetools inspect nginx:1.30-alpine` and write it as `FROM nginx:1.30-alpine@sha256:<digest>`.

**HttpOnly session cookie for the web app (optional, recommended).** Set `LOCKSTEP_USE_API_PROXY=true` on the frontend service. The nginx container then forwards `/lockstep/api/*` to `LOCKSTEP_API_BASE_URL`, the web app calls the API on its own origin, and its 30-day session is kept in an HttpOnly, `SameSite=Strict` cookie that page scripts cannot read (instead of `localStorage`). The extension keeps using its header token.

```powershell
gcloud run services update $WebService --region $Region --update-env-vars="LOCKSTEP_USE_API_PROXY=true"
```

**Cookie session with Firebase Hosting.** Firebase Hosting can forward `/lockstep/api/**` to the API service, which then serves the same routes under `/lockstep/api` (`PUBLIC_PATH_PREFIX`, default `/lockstep`) and names the cookie `__session`, the only cookie Firebase forwards:

```powershell
.\build-firebase-hosting.ps1 -CloudRunService $ApiService -CloudRunRegion $Region -GoogleClientId $GoogleClientId
firebase deploy --only hosting --config firebase.proxy.json
```

The script writes `firebase.proxy.json` (the tracked `firebase.json` plus the rewrite) and a `config.js` that calls the API on the page's own origin. Without `-CloudRunService` the build calls the API origin directly with a header token, as before.

## 10. Final production checks

After the Store version is available:

1. Install it from the Store in a clean Chrome profile.
2. Confirm the installed ID equals `$ExtensionId`.
3. Repeat sign-in and cross-client synchronization tests.
4. Check Cloud Run logs for authentication, CORS, or Firestore permission errors without logging request bodies.
5. Configure billing budgets, Cloud Run error/latency alerts, and Firestore backup/export procedures.
6. Keep at least one recovery key offline and test recovery using disposable data.
7. Remove unused localhost/test origins and test users when production rollout is complete.

## 11. Releasing updates

Deploy the API before the frontend and extension when a release adds API endpoints. Clients fall back to the older requests when `/api/v1/bootstrap` or `/api/v1/entries/batch` is not available yet, so either order works, but API-first gives the speed-up immediately.

The service worker needs no manual version bump: the container build and `build-firebase-hosting.ps1` stamp `webapp/sw.js` with a hash of the app's files, so every release gets its own cache and browsers install the complete new set before switching (a page never mixes files from two releases). Only Lockstep's own caches are cleaned up. An unbuilt copy (`RELEASE = "source"`, local runs and tests) refreshes files in the background instead.

For the API:

```powershell
.\mvnw.cmd test
gcloud run deploy $ApiService --source . --service-account $RuntimeServiceAccount
```

For the frontend:

```powershell
node --check webapp/app.js
node --check webapp/crypto-store.js
node --check webapp/sw.js
gcloud run deploy $WebService --source webapp --update-env-vars="LOCKSTEP_API_BASE_URL=$ApiOrigin,LOCKSTEP_GOOGLE_CLIENT_ID=$GoogleClientId"
```

The API and frontend now have independent revisions and can be rolled back separately.

For the extension, increment the manifest version, run the tests, rebuild the ZIP, upload it to the existing Chrome Web Store item, and submit the update for review. Never create a second Store item for an ordinary update because that would change the extension ID and break its OAuth redirect/origin configuration.

Authenticated client requests and session creation have a 45-second deadline (including response-body reads). A timed-out write can still have committed; queued mutations retain their identifiers for safe retries. Extension sign-in invalidates its previous application session before publishing Google credentials, so a failed or interrupted sign-in requires another sign-in instead of reusing a mismatched session. Vault change timestamps use Firestore commit time, and delta cursors use Firestore read time rather than API instance clocks. Each delta request performs one additional document read for its cursor.

Queued sync transports are bound to their original account/session and refuse work after sign-in changes. Client retries honor Retry-After; transient failures (no connection to the API, timeouts, server errors) are retried every 5 to 10 seconds with random jitter and no growing backoff, so a queued change arrives within about 10 seconds of the API recovering. A download that fails the same way is retried on the same schedule while the web app or the extension popup is open, even when nothing is waiting to upload. Signing out clears the retry delay, so a failure from an ended session never delays the next sign-in. Refused changes (conflicts, validation errors, a reset vault) and authentication failures are never retried in a loop. Retry state is kept in memory and resets when the client restarts; queued changes themselves are stored durably. Timeouts retain queued mutations and explicitly acknowledge that the server may already have committed the write.

Startup bootstrap and older-server fallback requests carry the initiating authentication snapshot; responses are checked before publishing vault state. Sync transports enforce cooldowns when requests execute, and retry callbacks recheck them before sending, including timers created before a later rate-limit response.

A restored network connection resets network-failure backoff, while preserving server Retry-After deadlines. API recovery without a connectivity event is picked up by the next 5 to 10 second retry.

Explicit Sign out in both clients confirms removal of this browser’s encrypted vault, keys, queued changes and ordering preferences. Unsynchronized data is lost after confirmation. Server data and other devices remain intact. Automatic session expiry/revocation and Sign out of all devices retain their existing behavior.

Explicit local erasure notifies other web tabs through a persistent storage event, locks their in-memory vaults, and clears their code rows. Mutations also verify the persisted wrapped key before writing, so a stale tab that misses the notification cannot recreate erased data. Reset enumeration and delete batches share a 25-second cleanup budget; timeout retains the reset marker for safe lease-based resumption.

Both clients accept backups containing up to 1,000 entries, matching the server vault limit. Backup imports are capped at 8 MB to accommodate encrypted exports with long Unicode labels. Extension imports retain their initiating owner/session and stop on authentication changes or locking, reporting partial progress. CORS exposes Retry-After to cross-origin web clients. Light-theme muted and positive text colors are shared between both clients and meet the tested 4.5:1 contrast threshold on secondary/canvas surfaces.

Passphrase-verified rotation metadata repair may inspect an existing changed wrapper without discarding the in-memory key first; missing wrappers after local erasure still reject stale operations. Recovery-key verification checks all entries at the current version in cancellable batches rather than limiting verification to the first twenty. Session-validation database timeouts return 503 BACKEND_UNAVAILABLE with Retry-After: 30.

Both clients load QR images through identical image-import.js helpers. Imports reject files over 20 MiB and images over 40 megapixels; common PNG/JPEG/GIF/WebP/BMP dimensions are checked from bounded headers before decode, with resize requests for known large images when orientation metadata is available. JPEG/PNG orientation is respected; uncertain orientation avoids resize distortion. Other supported formats are validated after decode. Decoded bitmaps and fallback object URLs are released on errors. The helper is included in offline caches and both static production build paths.

Unlock, legacy migration and session resume recheck a persistent erasure generation and wrapped-key identity after asynchronous cryptography. Concurrent session-snapshot exports share wrap-key creation and validate the key again before returning. Web imports bind their owner/session for the entire import, matching the extension; superseded extension sign-ins cannot publish setup/recovery flags. Future or out-of-range sync cursors repair through a full snapshot. Transient Firestore RPC failures use the retryable 503 response, and interrupted waits cancel their pending call.

New web sign-ins cancel work from the previous UI epoch; refresh callbacks cannot change a newer session’s lock screen, connectivity state or busy indicators. A superseded sign-in also cannot hide the newer sign-in’s loading overlay. Switching accounts clears the previous account’s in-memory key and visible rows while retaining its encrypted cache unless the user chooses Sign out.

### Central environment configuration

Copy `.env.example` to `.env` and configure the root file before running `./configure-clients.ps1` or `./run-local.ps1`. The web config, extension config, and extension manifest are generated and Git-ignored. Keep manifest metadata in `extension/manifest.template.json`. Public API origins automatically determine extension host permissions and CSP. The Firebase Hosting build reads the same variables and generates `firebase.runtime.json` for direct API access (`firebase deploy --only hosting --config firebase.runtime.json`); same-origin Cloud Run rewrites still use `firebase.proxy.json`.

The backend already loads the root `.env` with lower precedence than OS variables and now also reads the documented runtime/security switches from it. Production containers use platform environment variables or mounted secrets; `.env` is excluded from Docker contexts, hosting output and extension assets. Pass only public frontend variables to the web container. `GOOGLE_APPLICATION_CREDENTIALS` names a server-only file under ignored `secrets/`, or stays blank for Application Default Credentials. No Google client secret is used. Client IDs and URLs remain visible in browser output.

### Repeated builds and reloading deployment values

The client generator and hosting build read `.env` without modifying the terminal environment. Editing the file and rerunning either build therefore uses the edited values unless an explicit terminal override exists. For a terminal that previously imported old values, reload intentionally before deployment:

```powershell
. ./tools/Load-Env.ps1
Import-LockstepEnv -Path ./.env -OverrideExisting
```

This reload validates the complete file before changing the process environment. It does not deploy anything. Keep the existing backend/frontend variable allowlists when passing the loaded values to Cloud Run; do not upload the entire `.env` or server credentials to either client.

### Popup and export cancellation

The extension clears decrypted account rows and edit drafts when locking, signing out or entering recovery. Replies and settings animations from an older view cannot render over or hide the newer lock screen. Both vault modules also reject account-list, QR, plaintext-backup and recovery-key reads started before a lock, even if the vault is unlocked again before those reads finish. Rebuild the extension package to include these fixes; generated configuration alone does not update installed extension code.

Background web upload failures preserve the server's Retry-After cooldown; a swallowed upload error is never treated as a successful sync. Delayed retries check the account/session again before publishing queue counts. These cases are covered in `tests/e2e/startup-boundaries.test.js`.

Live shared-data refresh: current servers advertise `liveChanges` and provide an authenticated `/api/v1/events` SSE channel. Active webapp pages and extension popups fetch authoritative vault state as changes arrive, including additions, edits, deletions, passphrase/recovery-key changes and shared lock settings. Account writes commit a `changeSequence` notification marker in the same Firestore transaction; document listeners deliver changes across API instances. Notifications contain no vault data or credentials, and session credentials stay in request headers or the same-origin HttpOnly cookie. A changed key locks the receiving client and requires the current passphrase. Draft inputs remain intact unless a key/session change requires closing sensitive views; encrypted records can synchronize while editing. The 30-second timer and focus checks remain as fallback for older servers, interrupted streams and suspended clients. Reconnecting streams receive an initial invalidation to catch missed changes. Theme, pins and account order remain device-local. Deploy the backend, redeploy the webapp, and rebuild/release the extension to enable live updates on both clients.

Reconnect uploads: the webapp schedules its encrypted outbox immediately on the browser online event. An open extension popup notifies the worker to reset transient network backoff and schedule upload immediately; the worker also listens for online events and retains its retry timer/alarm for a closed popup. Browser suspension can delay background work. Explicit server Retry-After still takes precedence. Reconnect tests cover the popup open and the popup closed with a locked vault; acknowledged writes leave the queue without a reload or unlock.

Routine delta synchronization on current servers now uses `/api/v1/bootstrap` for wrapped-key metadata and ciphertext together. The server fences the response with vault revision checks, preventing a rotation between separate reads from mixing key and account versions. This replaces the separate lock-settings request during ordinary sync; older servers retain the legacy fallback. Startup still reuses its prefetched response. A changed key locks the receiving client before account decryption. Responses older than the locally known vault revision are rejected before cached lock settings or account ciphertext can be applied. If an account update and its tombstone overlap in one delta, deletion takes precedence in the API response and both client stores.

File-import cancellation: backup/QR preprocessing is tied to its originating vault view, and late recovery-file reads cannot refill a cleared form or replace a newer selection. Backup-password dialogs accept only one submission at a time; cancelled derivations cannot reset or close a later dialog. Both clients validate supported wrapping algorithms, salt size and bounded integer KDF parameters before starting derivation, including local vault records; valid encryption settings are unchanged.

Live connections use a four-minute lifetime, 15-second keepalives and automatic reconnection. Session replacement, sign-out and reset close the old session's stream. Each instance allows at most 2,000 streams and four per account. The web app's tabs in one browser share a single stream (one tab listens and passes changes to the others; another tab takes over when it closes), so a signed-in account normally holds two: one web app, one extension popup. When an account's four places are taken (for example by streams of closed popups or reloaded pages that the server has not yet noticed are gone), the oldest stream of the same client type, else the account's oldest, is closed to make room instead of refusing the new client; a client whose stream was closed reconnects and catches up. Only the per-instance limit refuses connections; those clients use the existing polling fallback. Streams consume Cloud Run request concurrency, so include connected clients in capacity planning. The bundled Nginx proxy disables buffering/cache and allows 300-second reads. Any additional proxy/CDN must pass `text/event-stream` responses without buffering. Cloud Run streams remain subject to its configured [request timeout](https://docs.cloud.google.com/run/docs/configuring/request-timeout); clients reconnect when a stream ends. Firebase Hosting rewrites or other gateways should be checked for streaming behavior in the deployed environment; use the direct API origin if a gateway buffers events.
