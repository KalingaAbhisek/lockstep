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
  --min=0 `
  --max=10 `
  --memory=512Mi `
  --cpu=1
```

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
  --set-env-vars="LOCKSTEP_API_BASE_URL=$ApiOrigin" `
  --min=0 `
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
2. Create `dist` and make an initial ZIP whose root contains `manifest.json` (not an outer `extension` folder):

   ```powershell
   New-Item -ItemType Directory -Force dist | Out-Null
   Compress-Archive -Path extension\* -DestinationPath dist\lockstep-extension-draft.zip -Force
   ```

3. In the Chrome Developer Dashboard choose **Add new item** and upload the draft ZIP.
4. Do not submit it yet. Copy the permanent item/extension ID shown by the dashboard.

The extension currently needs production-quality extension icons and store artwork before submission. Add at least the normal Manifest V3 icon assets and declare them in `manifest.json`; also prepare the screenshots and promotional assets requested by the Store dashboard.

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

Update `extension/config.js`:

```javascript
globalThis.AUTHSYNC_CONFIG = {
  apiBaseUrl: "https://YOUR_API_HOST",
  webBaseUrl: "https://YOUR_WEBAPP_HOST",
  googleClientId: "YOUR_WEB_OAUTH_CLIENT_ID.apps.googleusercontent.com"
};
```

Replace the development host permission in `extension/manifest.json`:

```json
"host_permissions": ["https://YOUR_API_HOST/*"]
```

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

Increment `version` in `extension/manifest.json` for every uploaded release. Then load the production-configured `extension` directory through `chrome://extensions` and test:

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
$Version = (Get-Content extension\manifest.json | ConvertFrom-Json).version
Compress-Archive -Path extension\* -DestinationPath "dist\lockstep-extension-$Version.zip" -Force
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
gcloud run deploy $WebService --source webapp --update-env-vars="LOCKSTEP_API_BASE_URL=$ApiOrigin"
```

The API and frontend now have independent revisions and can be rolled back separately.

For the extension, increment the manifest version, run the tests, rebuild the ZIP, upload it to the existing Chrome Web Store item, and submit the update for review. Never create a second Store item for an ordinary update because that would change the extension ID and break its OAuth redirect/origin configuration.
