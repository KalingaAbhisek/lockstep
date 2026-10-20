# Lockstep production deployment

## Recommended topology

Deploy the Spring Boot API and PWA together as one public **Google Cloud Run** service, use **Firestore in Native mode** in the same Google Cloud project, and distribute the Manifest V3 extension through the **Chrome Web Store**.

The PWA is already packaged from `server/src/main/resources/static` into the Spring Boot JAR. It does not need a separate frontend host. Keeping it on the API origin also avoids unnecessary cross-origin configuration for the web client.

Use one Google Cloud project for Cloud Run, Firestore, and OAuth. The examples below use PowerShell and these placeholders:

```powershell
$ProjectId = "YOUR_GOOGLE_CLOUD_PROJECT_ID"
$Region = "asia-south1"
$Service = "lockstep"
$RuntimeServiceAccount = "lockstep-runtime@$ProjectId.iam.gserviceaccount.com"
$GoogleClientId = "YOUR_WEB_OAUTH_CLIENT_ID.apps.googleusercontent.com"
```

Choose the Cloud Run region before creating Firestore. A nearby region such as `asia-south1` is appropriate for users primarily in India, but the Firestore locations available to the project and the desired user geography should determine the final choice. A Firestore database location cannot be changed after creation.

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
node --check server/src/main/resources/static/app.js
node --check extension/popup.js
node --check extension/service-worker.js
```

Do not deploy `.env`, anything under `secrets/`, a Firebase JSON key, recovery keys, exported OTP backups, or development logs.

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

The production Cloud Run URL and Chrome Web Store extension ID are added to this client later. Do not create a client secret for either browser client, and never put a client secret in the PWA or extension.

For a public OAuth app, host a public home page, privacy policy, and terms page on a domain you control. The privacy policy must accurately describe Google profile data, encrypted authenticator metadata/ciphertext, QR capture behavior, retention/deletion, and all processors used.

## 4. Deploy the backend and PWA to Cloud Run

The root `Dockerfile` builds the server and packages the PWA into the same image. The first deployment establishes the service URL:

```powershell
gcloud run deploy $Service `
  --source . `
  --allow-unauthenticated `
  --service-account $RuntimeServiceAccount `
  --set-env-vars="GOOGLE_WEB_CLIENT_ID=$GoogleClientId,GOOGLE_EXTENSION_CLIENT_ID=$GoogleClientId,FIREBASE_PROJECT_ID=$ProjectId,ALLOWED_ORIGINS=http://localhost:8080" `
  --min=0 `
  --max=10 `
  --memory=512Mi `
  --cpu=1
```

Read the assigned HTTPS URL:

```powershell
$WebOrigin = gcloud run services describe $Service --format="value(status.url)"
$WebOrigin
```

In the Web OAuth client, add `$WebOrigin` exactly under **Authorized JavaScript origins**. Do not add a trailing slash or path. It will look similar to:

```text
https://lockstep-xxxxxxxxxx-xx.a.run.app
```

Redeploy the configuration with the production web origin:

```powershell
gcloud run services update $Service `
  --update-env-vars="GOOGLE_WEB_CLIENT_ID=$GoogleClientId,GOOGLE_EXTENSION_CLIENT_ID=$GoogleClientId,FIREBASE_PROJECT_ID=$ProjectId,ALLOWED_ORIGINS=$WebOrigin"
```

Open `$WebOrigin`, sign in, configure lock protection, add a disposable test account, refresh, sign out/in, unlock, and verify the account remains available. Also install the PWA once on a phone and test offline code display.

### Optional custom domain

A custom HTTPS domain is preferable for a public product and is required for a polished OAuth home/privacy presence. Map a domain to Cloud Run or place a supported Google load balancer in front of it. After the domain works:

1. Add its exact origin to the OAuth client's Authorized JavaScript origins.
2. Change `$WebOrigin` to the custom origin.
3. Update `ALLOWED_ORIGINS` as shown below.
4. Use the custom origin in the extension configuration and host permission.

## 5. Obtain the permanent Chrome extension ID

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

## 6. Connect the production extension

Set the ID and origin locally:

```powershell
$ExtensionId = "YOUR_CHROME_WEB_STORE_EXTENSION_ID"
$ExtensionOrigin = "chrome-extension://$ExtensionId"
```

In the same Web OAuth client, add this exact **Authorized redirect URI**:

```text
https://YOUR_CHROME_WEB_STORE_EXTENSION_ID.chromiumapp.org/google
```

There is no trailing slash. The path `/google` is required by the implementation.

Update `extension/config.js`:

```javascript
globalThis.AUTHSYNC_CONFIG = {
  apiBaseUrl: "https://YOUR_PRODUCTION_HOST",
  googleClientId: "YOUR_WEB_OAUTH_CLIENT_ID.apps.googleusercontent.com"
};
```

Replace the development host permission in `extension/manifest.json`:

```json
"host_permissions": ["https://YOUR_PRODUCTION_HOST/*"]
```

Update Cloud Run CORS so it contains the exact PWA and extension origins:

```powershell
$AllowedOrigins = "$WebOrigin,$ExtensionOrigin"
gcloud run services update $Service --update-env-vars="ALLOWED_ORIGINS=$AllowedOrigins"
```

Keep `GOOGLE_WEB_CLIENT_ID` and `GOOGLE_EXTENSION_CLIENT_ID` set to the Web OAuth client ID used by the two clients. Cloud Run creates a new revision when the environment changes.

## 7. Test the store build locally

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

## 8. Complete the Chrome Web Store listing

In the item dashboard complete:

1. **Store listing:** clear single-purpose description, icon, screenshots, support URL, home page, and category.
2. **Privacy:** link the public privacy policy and truthfully disclose authentication information, name/email/profile data, user-provided OTP account metadata, encrypted synchronized records, and website content accessed only when the user explicitly starts QR capture.
3. **Permission justifications:**
   - `activeTab` and `scripting`: capture/decode only the currently visible tab after the user starts QR capture.
   - `identity`: open the Google OAuth sign-in flow.
   - `storage`: retain encrypted local vault data and device-local preferences.
   - `alarms`: perform scheduled background maintenance/refresh used by the extension.
   - production host permission: call only the Lockstep API.
4. **Limited Use:** make the required certification and put the Chrome Web Store Limited Use statement in the public privacy policy.
5. **Distribution:** start with Trusted testers or Unlisted for final production verification, then move to Public when ready.

Upload the final ZIP, submit it for review, and wait for approval. A new upload must have a higher manifest version.

## 9. Final production checks

After the Store version is available:

1. Install it from the Store in a clean Chrome profile.
2. Confirm the installed ID equals `$ExtensionId`.
3. Repeat sign-in and cross-client synchronization tests.
4. Check Cloud Run logs for authentication, CORS, or Firestore permission errors without logging request bodies.
5. Configure billing budgets, Cloud Run error/latency alerts, and Firestore backup/export procedures.
6. Keep at least one recovery key offline and test recovery using disposable data.
7. Remove unused localhost/test origins and test users when production rollout is complete.

## 10. Releasing updates

For the web/backend:

```powershell
.\mvnw.cmd test
gcloud run deploy $Service --source . --service-account $RuntimeServiceAccount
```

Cloud Run keeps prior revisions so a traffic rollback remains possible.

For the extension, increment the manifest version, run the tests, rebuild the ZIP, upload it to the existing Chrome Web Store item, and submit the update for review. Never create a second Store item for an ordinary update because that would change the extension ID and break its OAuth redirect/origin configuration.
