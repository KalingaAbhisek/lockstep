// Trusted Types are enforced (manifest CSP), so the scripts this worker loads go through a policy that only
// accepts its own three files.
const WORKER_SCRIPTS = ["config.js", "vendor/argon2id.js", "crypto-store.js"];
const workerScriptPolicy = globalThis.trustedTypes?.createPolicy?.("lockstep-scripts", {
    createScriptURL(url) {
        if (!WORKER_SCRIPTS.includes(url)) throw new TypeError(`Script URL not allowed: ${url}`);
        return url;
    }
});
importScripts(...WORKER_SCRIPTS.map((url) => workerScriptPolicy ? workerScriptPolicy.createScriptURL(url) : url));

// The QR scanner script runs inside web pages; it only needs messaging, never storage. Restrict both storage
// areas to the extension's own pages (where the browser supports it for an area; otherwise this is a no-op).
chrome.storage.local.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => {});
chrome.storage.session.setAccessLevel?.({ accessLevel: "TRUSTED_CONTEXTS" }).catch(() => {});

// What the server supports (Argon2id key protection, encrypted names) is kept in storage: Chrome stops this
// worker when it is idle, and a restarted worker must not protect a new or rotated key with the older
// PBKDF2 method just because it has not asked the server yet.
const SERVER_FEATURES_KEY = "serverFeatures";
function applyServerFeatures(features) {
    LockstepVault.setLabelEncryption(features.includes("encryptedLabels"));
    LockstepVault.setArgon2idWrapping(features.includes("argon2idWrapping"));
}
let serverFeaturesKnown = false;
const serverFeaturesRestored = chrome.storage.local.get(SERVER_FEATURES_KEY).then((stored) => {
    if (Array.isArray(stored[SERVER_FEATURES_KEY]) && !serverFeaturesKnown) { applyServerFeatures(stored[SERVER_FEATURES_KEY]); serverFeaturesKnown = true; }
}).catch(() => {});
async function rememberServerFeatures(features) {
    const list = Array.isArray(features) ? features.filter((feature) => typeof feature === "string") : [];
    applyServerFeatures(list);
    serverFeaturesKnown = true;
    await chrome.storage.local.set({ [SERVER_FEATURES_KEY]: list }).catch(() => {});
}
// Before a key is wrapped (passphrase setup or change, rotation, recovery-key import): make sure the
// server's features are known, asking it once if this browser has never seen them.
async function ensureServerFeatures() {
    await serverFeaturesRestored;
    if (!serverFeaturesKnown) await fetchStartupState(await subject()).catch(() => null);
}

let lastSyncError = null;
// When the last sync failed for a temporary reason (no connection to Lockstep, a timeout, a server error, "try
// later", a retry delay still running): when to try again. An open popup reloads its list then (5 to 10 seconds,
// or the server's Retry-After), even when nothing is waiting to upload. Never set for sign-in, validation or
// conflict errors.
let syncRetryAt = 0;
function noteSyncFailure(owner, error) {
    const status = Number(error?.status || 0);
    const temporary = error?.code === "SYNC_COOLDOWN" || (!["SESSION_CHANGED", "SESSION_EXPIRED", "SESSION_REVOKED", "VAULT_LOCKED", "ACCOUNT_MISSING", "VAULT_REPLACED"].includes(error?.code)
        && (!status || status === 408 || status === 429 || status >= 500));
    // Waiting out a retry delay that is already running: try again the moment it ends (it is the 5-10 s spacing).
    const spacing = error?.code === "SYNC_COOLDOWN" ? 250 : TRANSIENT_RETRY_MIN_MILLIS + Math.random() * (TRANSIENT_RETRY_MAX_MILLIS - TRANSIENT_RETRY_MIN_MILLIS);
    syncRetryAt = temporary ? Date.now() + Math.max(error?.retryAfterMillis || 0, retryDelay(owner), spacing) : 0;
}
let authenticationGeneration = 0;
let authenticationTransition = false;
let authenticationWrites = Promise.resolve();
function writeAuthentication(action) {
    const next=authenticationWrites.catch(()=>null).then(action);
    authenticationWrites=next.catch(()=>null);
    return next;
}
async function authenticationSnapshot() {
    const generation=authenticationGeneration;
    const stored=await chrome.storage.local.get(["vaultSubject","appSessionId"]);
    return {generation,owner:stored.vaultSubject,session:stored.appSessionId};
}
async function authenticationMatches(snapshot) {
    const current=await authenticationSnapshot();
    return current.generation===snapshot.generation && authenticationGeneration===snapshot.generation
        && current.owner===snapshot.owner && current.session===snapshot.session;
}
let tokenRefreshPromise = null;
let activeScannerTabId = null;
const PENDING_SYNC_ALARM = "lockstep-pending-sync";
const CONNECTIVITY_ALARM = "lockstep-connectivity-check";
const DEVICE_LOCK_ALARM = "lockstep-device-lock-check";
const DEVICE_LOCK_CHECK_MINUTES = 0.5;
const DEVICE_SUSPEND_GRACE_MS = 10000;
// Background session check and sync while the popup is closed. The popup checks again whenever it opens.
// Background session check while the popup is closed (a revoked session is cleared within this time). The
// popup checks again every time it opens, so this can be infrequent.
const BACKGROUND_CHECK_MILLIS = 30 * 60 * 1000;
// Retry of changes still waiting to upload. It makes no request when nothing is pending.
const BACKGROUND_SYNC_MINUTES = 5;
const SESSION_REVOKED_NOTICE_KEY = "sessionRevokedNotice";
let pendingSyncPromise = null;
let pendingSyncTimeout = null;
let connectivityPollPromise = null;
let connectivityTimeout = null;
// Short-lived, in-memory results that let one popup opening share a single startup request.
let recentLockConfig = null;   // { owner, config, at } from the latest successful lock read
let prefetchedVault = null;    // { owner, entries, generation, fetchedAt } from the startup bootstrap
let bootstrapUnsupported = false;
let batchUnsupported = false;
let changesUnsupported = false;
const RECENT_LOCK_MILLIS = 10000;
const PREFETCHED_VAULT_MILLIS = 30000;
function forgetRecentReads() { recentLockConfig = null; prefetchedVault = null; }
function rememberLockConfig(owner, config) { recentLockConfig = { owner, config, at: Date.now() }; }
function recentLock(owner) {
    return recentLockConfig && recentLockConfig.owner === owner && Date.now() - recentLockConfig.at < RECENT_LOCK_MILLIS ? recentLockConfig.config : null;
}
function takePrefetchedVault(owner) {
    const prefetched = prefetchedVault;
    prefetchedVault = null;
    if (!prefetched || prefetched.owner !== owner || Date.now() - prefetched.fetchedAt > PREFETCHED_VAULT_MILLIS) return null;
    if(!prefetched.authentication || prefetched.authentication.generation !== authenticationGeneration) return null;
    return prefetched;
}
const ALLOWED_LOCK_TIMEOUTS = new Set([300,600,900,1200,1500,1800,2100,2400,2700,3000,3300,3600,7200,14400,28800,43200,86400,172800,604800]);

async function schedulePendingSync(delay = 0) {
    delay=Math.max(delay,retryDelay(await subject().catch(()=>null)));
    clearTimeout(pendingSyncTimeout);
    pendingSyncTimeout=null;
    pendingSyncTimeout=setTimeout(()=>retryPendingSync().catch(()=>null),delay);
    return chrome.alarms.create(PENDING_SYNC_ALARM,{when:Date.now()+Math.max(1,delay)});
}

async function stopPendingSync() {
    clearTimeout(pendingSyncTimeout);pendingSyncTimeout=null;
    await chrome.alarms.clear(PENDING_SYNC_ALARM);
}

// A change the server refused for good (it was dropped from the queue) is reported once, the next time the
// popup asks for the sync state.
async function rememberSyncNotice(message) {
    if (message) await chrome.storage.session.set({ syncNotice: message }).catch(() => {});
}

async function retryPendingSync() {
    if(pendingSyncPromise)return pendingSyncPromise;
    pendingSyncPromise=(async()=>{
        clearTimeout(pendingSyncTimeout);pendingSyncTimeout=null;
        await chrome.alarms.clear(PENDING_SYNC_ALARM);
        let owner;
        try{owner=await subject();}catch{return;}
        let pending=await LockstepVault.pendingCount(owner);
        if(!pending)return;
        if(retryDelay(owner)>0){await schedulePendingSync(retryDelay(owner));return;}
        if(!navigator.onLine){await schedulePendingSync(10000);return;}
        try{await LockstepVault.flushOutbox(owner,transport(owner));syncRetryStates.delete(owner);lastSyncError=null;}
        catch(error){
            if(error?.dropped){await rememberSyncNotice(error.message);lastSyncError=null;}
            else lastSyncError=error?.message||"Lockstep could not sync. It will try again.";
        }
        if(!(await chrome.storage.local.get("vaultSubject")).vaultSubject){await stopPendingSync();return;}
        pending=await LockstepVault.pendingCount(owner);
        if(pending)await schedulePendingSync(TRANSIENT_RETRY_MIN_MILLIS);
        else await stopPendingSync();
    })().finally(()=>{pendingSyncPromise=null;});
    return pendingSyncPromise;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const actions = {
        LOGIN: login,
        CONFIRM_RECENT_GOOGLE_SIGN_IN: async () => {
            const allowed = ["ROTATE_ENCRYPTION_KEY", "SET_LOCK_CONFIG", "RESET_VAULT", "DELETE_ENTRY", "LOGOUT_ALL", "IMPORT_RECOVERY_KEY", "UPGRADE_PROTECTION"];
            if (!allowed.includes(message.action)) throw new Error("This action cannot request Google confirmation.");
            await ensureRecentGoogleSignIn({ confirmed: true });
            // Keep the operation in the worker: Chrome may close the popup when the account chooser opens.
            return actions[message.action]();
        },
        LOGOUT: () => logout(message.authentication),
        LOGOUT_ALL: logoutEverywhere,
        LIST_ENTRIES: () => withUnlocked(listEntries),
        GET_CACHED_ENTRIES: () => withUnlocked(localEntries),
        START_SCAN: () => withUnlocked(startScan),
        ADD_OTP_URI: () => withUnlocked(() => addOtpUri(message.otpAuthUri)),
        IMPORT_ENTRIES: () => withUnlocked(() => importEntries(message.otpAuthUris)),
        EXPORT_ENTRIES: () => withUnlocked(() => exportEntries(message.passcode, message.backupPassword)),
        CHECK_EXPORT_PASSPHRASE: () => withUnlocked(() => requireExportPassphrase(message.passcode).then(() => true)),
        DECRYPT_BACKUP: () => withUnlocked(() => LockstepVault.decryptBackup(message.text, message.password)),
        GET_ENTRY_QR: () => withUnlocked(() => localOtpUri(message.id)),
        GET_CURRENT_CODE: () => withUnlocked(async () => LockstepVault.currentCode(await subject(),message.id)),
        GET_VAULT_STATE: vaultState,
        GET_LOCAL_STATE: localVaultState,
        GET_LOCK_CONFIG: getLockConfig,
        CHECK_REMOTE_LOCK: checkRemoteLock,
        GET_CHANGE_STREAM_AUTH: changeStreamAuthentication,
        // The server says this session ended. Confirmed with one request before signing out: an answer that the
        // session was replaced or expired signs out (api() does that); if it is still valid the popup reconnects;
        // if the server cannot be reached the popup asks again shortly ("UNCONFIRMED").
        LIVE_SESSION_ENDED: async () => {
            if (!await authenticationMatches(message.authentication)) throw coded("SESSION_CHANGED","Sign-in changed.");
            try { await api("/api/v1/session", { expectedAuthentication: message.authentication }); return { active: true }; }
            catch (error) {
                if (["SESSION_REVOKED","SESSION_EXPIRED","SESSION_CHANGED"].includes(error?.code)) throw error;
                if (!message.final) throw coded("UNCONFIRMED", "Lockstep could not confirm the session. Trying again.");
                const messageText = "This Lockstep session ended on another device. Sign in again.";
                if (!await invalidateAuthentication(messageText,message.authentication)) throw coded("SESSION_CHANGED","Sign-in changed.");
                throw coded("SESSION_REVOKED",messageText);
            }
        },
        LIVE_SYNC: async () => {
            if (!await authenticationMatches(message.authentication)) throw coded("SESSION_CHANGED","Sign-in changed.");
            forgetRecentReads();
            return synchronize(true);
        },
        RESUME_VAULT: resumeVault,
        TOUCH_VAULT: touchVault,
        SET_LOCK_CONFIG: () => message.initialSetup ? setLockConfig(message.passcode, message.timeoutSeconds, message.lockOnScreenLock, true) : withUnlocked(() => setLockConfig(message.passcode, message.timeoutSeconds, message.lockOnScreenLock, false)),
        VERIFY_LOCK: () => verifyLock(message.passcode),
        ADOPT_SERVER_VAULT: () => adoptServerVaultNow(message.passcode),
        LOCK_VAULT: lockVault,
        REMOVE_LOCK: removeLock,
        UPGRADE_PROTECTION: () => withUnlocked(() => upgradeProtection(message.passcode)),
        UPDATE_ENTRY: () => withUnlocked(() => updateEntry(message.id, message.issuer, message.accountName)),
        RESCUE_STRANDED: () => withUnlocked(async () => { const rescued = await LockstepVault.rescueStrandedEntries(await subject(), message.passcode); if (rescued) await synchronize().catch(() => null); return rescued; }),
        RETRY_LOCAL_ONLY: () => withUnlocked(async () => { const queued = await LockstepVault.retryLocalOnly(await subject(), message.id); if (queued) await synchronize().catch(() => null); return queued; }),
        DELETE_ENTRY: () => withUnlocked(() => deleteEntry(message.id, message.passcode)),
        EXPORT_RECOVERY_KEY: () => withUnlocked(() => exportRecoveryKey(message.passcode)),
        IMPORT_RECOVERY_KEY: () => message.recoveryMode ? importRecoveryKey(message.recoveryKey, message.passcode) : withUnlocked(() => importRecoveryKey(message.recoveryKey, message.passcode)),
        RESET_VAULT: () => resetVault(message.passcode),
        ROTATE_ENCRYPTION_KEY: () => withUnlocked(() => rotateEncryptionKey(message.passcode)),
        GET_SYNC_STATE: syncState,
        CHECK_CONNECTIVITY: checkConnectivity,
        CHECK_SESSION: checkActiveSession,
        NETWORK_ONLINE: networkRestored,
        SYNC_NOW: synchronize,
        OPEN_PRIVACY: openPrivacyPolicy
    };
    if (!Object.hasOwn(actions, message.type)) return false;
    // Only the extension's own pages may use these actions. The QR scanner script runs inside web pages,
    // so messages from it may only add a scanned account.
    const fromExtensionPage = sender.id === chrome.runtime.id && String(sender.url || "").startsWith(chrome.runtime.getURL(""));
    const fromScanner = sender.id === chrome.runtime.id && Boolean(sender.tab) && message.type === "ADD_OTP_URI";
    if (!fromExtensionPage && !fromScanner) {
        sendResponse({ ok: false, error: "This action is not available here." });
        return false;
    }
    // A scanned account is accepted only from the tab where the user started the scan.
    const allowed = fromExtensionPage ? Promise.resolve(true) : scannerTabMatches(sender.tab.id);
    allowed.then((ok) => { if (!ok) throw new Error("This action is not available here."); return actions[message.type](); })
        .then(data => sendResponse({ ok: true, data }))
        .catch(error => sendResponse({ ok: false, error: error?.message || "The requested extension action failed.", code: error?.code, retryAfterMillis:error?.retryAfterMillis }));
    return true;
});

async function scannerTabMatches(tabId) {
    if (activeScannerTabId !== null) return activeScannerTabId === tabId;
    const stored = await chrome.storage.session.get("activeScannerTabId").catch(() => ({}));
    return stored.activeScannerTabId === tabId;
}

async function openPrivacyPolicy() {
    const baseUrl = String(AUTHSYNC_CONFIG.webBaseUrl || "").replace(/\/+$/, "");
    if (!baseUrl) throw new Error("The Lockstep web app URL is not configured.");
    await chrome.tabs.create({ url: `${baseUrl}/privacy.html` });
    return true;
}

async function login() {
    const generation=++authenticationGeneration;
    authenticationTransition=true;
    const check=()=>{if(authenticationGeneration!==generation)throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");};
    try {
        const claims=await authorize(true);check();
        await chrome.storage.local.remove(SESSION_REVOKED_NOTICE_KEY);check();
        await registerAppSession();check();
        const authentication=await authenticationSnapshot();check();
        if(authentication.owner!==claims.sub)throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
        const exists=await backendAccountExists(authentication);check();
        await writeAuthentication(async()=>{
            check();
            if(!await authenticationMatches(authentication))throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
            if(!exists){
                await LockstepVault.clearSubject(claims.sub);check();
                await chrome.storage.session.remove(REPLACED_VAULT_KEY);check();
                await chrome.storage.local.remove("cachedLockConfig");check();
                await chrome.storage.session.set({newAccountSetupAuthorized:true});check();
                lastSyncError=null;
                return;
            }
            await chrome.storage.session.remove("newAccountSetupAuthorized");check();
            const state=await LockstepVault.keyState(claims.sub);check();
            if(state==="none")await chrome.storage.session.set({restoreAuthorized:true});
            else await chrome.storage.session.remove("restoreAuthorized");
            check();
        });
        check();
        if(exists){
            const state=await LockstepVault.keyState(claims.sub);check();
            await synchronize(state==="none").catch(error=>{if(error.code==="SESSION_CHANGED")throw error;});check();
        }
        return {email:claims.email,displayName:claims.name||claims.given_name||claims.email,newAccount:!exists};
    }finally{if(authenticationGeneration===generation)authenticationTransition=false;}
}

// Resetting the vault, rotating the recovery key, replacing the passphrase and signing out of every device
// need a Google sign-in from the last few minutes (the server allows five). A silent refresh is tried
// first; if Google needs the user, the popup asks for confirmation before opening Google's account chooser.
// Only a sign-in the user completed in Google's window counts: a token renewed silently in the background
// (prompt=none) also has a fresh issue time, but proves nobody is at the keyboard. The server cannot tell the
// two apart from Google's token, so the extension enforces it here.
const RECENT_SIGN_IN_MILLIS = 4 * 60 * 1000;
async function hasRecentGoogleSignIn() {
    const stored = await storedGoogleToken();
    if (!stored.idToken || !(stored.tokenExpiry >= Date.now() + 30000)) return false;
    const claims = parseClaims(stored.idToken);
    const { interactiveSignInAt } = await chrome.storage.session.get("interactiveSignInAt");
    return Boolean(claims?.iat && Date.now() - claims.iat * 1000 < RECENT_SIGN_IN_MILLIS
        && Number(interactiveSignInAt) > Date.now() - RECENT_SIGN_IN_MILLIS);
}
async function ensureRecentGoogleSignIn({ interactive = true, confirmed = false } = {}) {
    if (await hasRecentGoogleSignIn()) return true;
    const owner = await subject();
    if (!interactive) return false;
    if (!confirmed) throw coded("REAUTH_REQUIRED", "Confirm it is you: sign in with Google again to continue.");
    try { await authorize(true, owner); }
    catch (error) {
        // Chrome reports a closed or cancelled Google window as "The user did not approve access."
        if (error?.code || !/did not approve|cancel|closed/i.test(String(error?.message))) throw error;
        throw coded("REAUTH_CANCELLED", "Google confirmation was cancelled. Nothing was changed.");
    }
    if (await hasRecentGoogleSignIn()) return true;
    throw coded("REAUTH_REQUIRED", "Confirm it is you: sign in with Google again to continue.");
}

async function authorize(interactive, expectedSubject = null) {
    const generation=authenticationGeneration;
    const { googleClientId } = AUTHSYNC_CONFIG;
    if (googleClientId.startsWith("REPLACE_")) throw new Error("Set googleClientId in extension/config.js first.");
    const redirectUri = chrome.identity.getRedirectURL("google");
    const nonce = crypto.randomUUID();
    const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
    url.search = new URLSearchParams({
        client_id: googleClientId, response_type: "id_token", redirect_uri: redirectUri,
        scope: "openid email profile", nonce, prompt: interactive ? "select_account" : "none"
    });
    const callback = await chrome.identity.launchWebAuthFlow({ url: url.toString(), interactive });
    const idToken = new URL(callback.replace("#", "?")).searchParams.get("id_token");
    if (!idToken) throw new Error("Google sign-in did not complete. Try again.");
    const claims = parseClaims(idToken);
    if (claims.nonce !== nonce) throw new Error("Google sign-in could not be verified. Try again.");
    if (expectedSubject && claims.sub !== expectedSubject) throw coded("WRONG_ACCOUNT", "Continue with the Google account this vault belongs to.");
    const local = await chrome.storage.local.get("vaultSubject");
    if (!interactive && local.vaultSubject && local.vaultSubject !== claims.sub) {
        throw coded("SESSION_EXPIRED", "Session expired. Sign in with Google again.");
    }
    await writeAuthentication(async()=>{
        if(generation!==authenticationGeneration)throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
        // Invalidate the previous application session before publishing a different sign-in.
        // This persists across worker termination, unlike authenticationTransition.
        if (interactive && !expectedSubject) {
            forgetRecentReads();
            await chrome.storage.local.remove(["appSessionId", "appSessionExpiry", "cachedLockConfig"]);
        }
        await chrome.storage.session.set({ idToken, tokenExpiry: claims.exp * 1000, ...(interactive ? { interactiveSignInAt: Date.now() } : {}) });
        await chrome.storage.local.set({ vaultSubject: claims.sub, vaultDisplayName: claims.name || claims.given_name || claims.email || "" });
    });
    return claims;
}

async function logout(expected = null) {
    const authentication=await authenticationSnapshot();
    if(expected && (expected.owner!==authentication.owner || expected.session!==authentication.session))throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
    if(!await invalidateAuthentication("",authentication,true))throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
    // Local removal succeeds independently of network availability. Revoke only the captured session.
    if(navigator.onLine && authentication.session)fetch(AUTHSYNC_CONFIG.apiBaseUrl+"/api/v1/session",{
        method:"DELETE",cache:"no-store",signal:AbortSignal.timeout(45000),
        headers:{"X-Lockstep-Subject":authentication.owner,"X-Lockstep-Client":"extension","X-Lockstep-Session":authentication.session}
    }).catch(()=>null);
}

// Ends every Lockstep session of this account (all browsers and this extension). Unlike a normal sign-out
// it must reach the server, so it fails (and keeps this device signed in) when offline.
async function logoutEverywhere() {
    await ensureRecentGoogleSignIn();
    const authentication=await authenticationSnapshot();
    await api("/api/v1/session?all=true", { method: "DELETE" });
    await invalidateAuthentication("",authentication);
    return true;
}

async function logoutLocally() {
    await invalidateAuthentication();
}

async function invalidateAuthentication(message = "", expected = null, erase = false) {
    return writeAuthentication(async()=>{
        const snapshot=expected||await authenticationSnapshot();
        if(!await authenticationMatches(snapshot))return false;
        if(erase && snapshot.owner) {
            LockstepVault.lock(snapshot.owner);
            await LockstepVault.clearSubject(snapshot.owner);
            await chrome.storage.local.remove(["pinnedEntryIds","entryOrder"]);
        }
        authenticationGeneration++;
        forgetRecentReads();
        // A retry delay belongs to the session that ended: the next sign-in syncs at once.
        syncRetryStates.clear(); syncRetryAt = 0; lastSyncError = null;
        if(snapshot.owner)LockstepVault.lock(snapshot.owner);
        await stopPendingSync();
        await chrome.storage.session.clear();
        await chrome.storage.local.remove(["vaultSubject", "vaultDisplayName", "cachedLockConfig", "appSessionId", "appSessionExpiry", "idToken", "tokenExpiry"]);
        if(message)await chrome.storage.local.set({[SESSION_REVOKED_NOTICE_KEY]:message});
        return true;
    });
}

async function subject() {
    const tokenState=await storedGoogleToken();
    if(tokenState.idToken)return parseClaims(tokenState.idToken).sub;
    const local = await chrome.storage.local.get(["vaultSubject", "vaultDisplayName"]);
    if (!local.vaultSubject) throw new Error("Sign in with Google first.");
    return local.vaultSubject;
}

function coded(code, message) { const error = new Error(message); error.code = code; return error; }

async function withUnlocked(action) {
    const owner = await subject();
    await enforceDeviceSuspendLock(await chrome.alarms.get(DEVICE_LOCK_ALARM));
    await enforceTimedLock(owner);
    if (!LockstepVault.isUnlocked(owner)) throw coded("VAULT_LOCKED", "Vault locked. Unlock it to continue.");
    const result=await action();
    if(!LockstepVault.isUnlocked(owner))throw coded("VAULT_LOCKED","Lockstep locked before it finished. Your change was saved.");
    return result;
}

async function cachedLockConfig() {
    const config = (await chrome.storage.local.get("cachedLockConfig")).cachedLockConfig || { enabled: true, timeoutSeconds: 300, lockOnScreenLock: false };
    const timeout=Number(config.timeoutSeconds);
    return { ...config, timeoutSeconds: ALLOWED_LOCK_TIMEOUTS.has(timeout) ? timeout : 300, lockOnScreenLock:Boolean(config.lockOnScreenLock) };
}

async function persistUnlockedSession(owner, config = null) {
    const lock = config || await cachedLockConfig();
    const lastUnlockedAt = Date.now();
    if (!lock.enabled) {
        await chrome.alarms.clear("lockstep-lock");
        await chrome.storage.session.remove("unlockedMaster");
        await chrome.storage.session.set({ lastUnlockedAt });
        return;
    }
    // The vault key is kept for the worker's restarts only encrypted, with a non-extractable key in IndexedDB.
    const snapshot = await LockstepVault.exportSessionKey(owner, await sessionWrapId()).catch(() => null);
    if (!LockstepVault.isUnlocked(owner)) { await chrome.storage.session.set({ lastUnlockedAt }); return; } // locked meanwhile
    await chrome.storage.session.set({ lastUnlockedAt, unlockedMaster: snapshot ? { subject: owner, snapshot } : null });
    chrome.alarms.create("lockstep-lock",{when:lastUnlockedAt+lock.timeoutSeconds*1000});
}

// Identifies this browser session's key for the sealed vault key (storage.session is emptied when the browser
// closes). Shared by concurrent callers, so two first-time callers cannot create different IDs.
let sessionWrapIdPromise = null;
function sessionWrapId() {
    sessionWrapIdPromise ||= (async () => {
        const stored = await chrome.storage.session.get("sessionWrapId");
        if (stored.sessionWrapId) return stored.sessionWrapId;
        const id = crypto.randomUUID();
        await chrome.storage.session.set({ sessionWrapId: id });
        return id;
    })().catch((error) => { sessionWrapIdPromise = null; throw error; });
    return sessionWrapIdPromise;
}

// Counts real locks: the Lock button, the screen locking or the device sleeping, and a lock that ends an open
// vault (timeout, sign-out). An unlock that was still running when one happened sees a different count and
// gives up, so the lock always wins. Routine checks that find the vault already locked do not count, so they
// cannot make a correct passphrase fail.
let lockEpoch = 0;
// Unlocks still running. Between opening the key and recording the unlock time, a routine check (timeout,
// popup refresh, worker resume) would see an open vault without an unlock time and lock it, failing a correct
// passphrase. Those checks leave a running unlock alone; real locks (explicit, or a key change) still win.
let unlocksInProgress = 0;

async function clearRoutineSession(owner) {
    if (unlocksInProgress > 0) return;
    await clearUnlockedSession(owner);
}

async function clearUnlockedSession(owner, explicit = false) {
    const wasOpen = LockstepVault.isUnlocked(owner) || Boolean((await chrome.storage.session.get("lastUnlockedAt")).lastUnlockedAt);
    if (explicit || wasOpen) lockEpoch++;
    LockstepVault.lock(owner);
    const { sessionWrapId: wrapId } = await chrome.storage.session.get("sessionWrapId");
    if (wrapId) LockstepVault.forgetSessionKey(owner, wrapId).catch(() => null);
    const scannerState=await chrome.storage.session.get("activeScannerTabId");
    const scannerTabId=activeScannerTabId??scannerState.activeScannerTabId??null;
    await chrome.storage.session.remove(["lastUnlockedAt", "unlockedMaster", "activeScannerTabId"]);
    await chrome.alarms.clear("lockstep-lock");
    if(scannerTabId!==null)chrome.tabs.sendMessage(scannerTabId,{type:"AUTHSYNC_CANCEL_QR"}).catch(()=>null);
    activeScannerTabId=null;
    void schedulePendingSync(0);
}

async function enforceTimedLock(owner) {
    const config = await cachedLockConfig();
    if (!config.enabled) return;
    const session = await chrome.storage.session.get("lastUnlockedAt");
    if (!session.lastUnlockedAt || Date.now() - session.lastUnlockedAt >= config.timeoutSeconds * 1000) await clearRoutineSession(owner);
}

async function resumeVault() {
    const owner = await subject();
    const config = await getLockConfig();
    if (!config.enabled) { await clearUnlockedSession(owner); return false; }
    const session = await chrome.storage.session.get(["lastUnlockedAt", "unlockedMaster"]);
    if (!session.lastUnlockedAt || Date.now() - session.lastUnlockedAt >= config.timeoutSeconds * 1000) {
        if (unlocksInProgress > 0) return LockstepVault.isUnlocked(owner);
        await clearUnlockedSession(owner); return false;
    }
    if (!LockstepVault.isUnlocked(owner)) {
        if (session.unlockedMaster?.subject !== owner || !await LockstepVault.restoreSessionKey(owner, session.unlockedMaster.snapshot, await sessionWrapId())) {
            await clearUnlockedSession(owner); return false;
        }
    }
    return true;
}

async function touchVault() {
    const owner = await subject();
    if (!LockstepVault.isUnlocked(owner)) return false;
    await persistUnlockedSession(owner);
    return true;
}

async function token() {
    const authentication=await authenticationSnapshot();
    const stored=await storedGoogleToken();
    if(stored.idToken&&stored.tokenExpiry>=Date.now()+30000)return stored.idToken;
    try {
        tokenRefreshPromise ||= authorize(false).finally(() => { tokenRefreshPromise = null; });
        await tokenRefreshPromise;
        const refreshed = await storedGoogleToken();
        if (refreshed.idToken && refreshed.tokenExpiry >= Date.now() + 30000) return refreshed.idToken;
    } catch {}
    await writeAuthentication(async()=>{
        if(!await authenticationMatches(authentication))throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
        await chrome.storage.session.remove(["idToken","tokenExpiry"]);
    });
    throw coded("SESSION_EXPIRED", "Session expired. Sign in with Google again.");
}

async function validStoredGoogleToken(){
    const stored=await storedGoogleToken();
    return stored.idToken&&stored.tokenExpiry>=Date.now()+30000?stored.idToken:"";
}

async function storedGoogleToken(){
    return chrome.storage.session.get(["idToken","tokenExpiry"]);
}

async function backendAccountExists(authentication = undefined) {
    return (await api("/api/v1/account",{expectedAuthentication:authentication})).exists;
}

// While the popup's startup request runs, a sync waits for it and reuses its vault list.
let startupInFlight = null;

// What the popup can show before any network request: who is signed in, whether this device holds the
// protected vault, the last known lock settings and whether the vault is still unlocked (within the lock
// timeout). Nothing here waits for the server; GET_VAULT_STATE checks the server alongside.
async function localVaultState() {
    const local = await chrome.storage.local.get(["vaultSubject", "vaultDisplayName", "cachedLockConfig", "appSessionId", "appSessionExpiry"]);
    const owner = local.vaultSubject;
    if (!owner || !local.appSessionId || !(Number(local.appSessionExpiry) > Date.now())) return { hasSubject: Boolean(owner), usable: false };
    const keyState = await LockstepVault.keyState(owner);
    const config = local.cachedLockConfig;
    if (keyState !== "wrapped" || !config?.enabled) return { hasSubject: true, usable: false };
    const timeout = ALLOWED_LOCK_TIMEOUTS.has(Number(config.timeoutSeconds)) ? Number(config.timeoutSeconds) : 300;
    let unlocked = LockstepVault.isUnlocked(owner);
    const session = await chrome.storage.session.get(["lastUnlockedAt", "unlockedMaster"]);
    const fresh = session.lastUnlockedAt && Date.now() - session.lastUnlockedAt < timeout * 1000;
    if (!fresh && unlocksInProgress > 0) unlocked = false; // an unlock is still running: report locked, leave it be
    else if (!fresh) { if (unlocked) await clearUnlockedSession(owner); unlocked = false; }
    else if (!unlocked && session.unlockedMaster?.subject === owner) unlocked = await LockstepVault.restoreSessionKey(owner, session.unlockedMaster.snapshot, await sessionWrapId());
    return { hasSubject: true, usable: true, displayName: local.vaultDisplayName || "", lockConfig: { ...config, timeoutSeconds: timeout, enabled: true }, unlocked };
}

// Single source of truth for popup routing: who is signed in, is the Google token usable,
// and does this device actually hold the vault master key.
async function vaultState() {
    const pending = vaultStateNow();
    const marker = pending.catch(() => null);
    startupInFlight = marker;
    try { return await pending; }
    finally { if (startupInFlight === marker) startupInFlight = null; }
}

async function vaultStateNow() {
    const local = await chrome.storage.local.get(["vaultSubject", "vaultDisplayName"]);
    const session = await storedGoogleToken();
    const sessionClaims = session.idToken ? parseClaims(session.idToken) : null;
    const owner = sessionClaims?.sub || local.vaultSubject;
    if (!owner) return { hasSubject: false };
    await activeAppSession();
    const validSession = true;
    const refreshedSession = await storedGoogleToken();
    const refreshedClaims = refreshedSession.idToken ? parseClaims(refreshedSession.idToken) : sessionClaims;
    const refreshedLocal = await chrome.storage.local.get("vaultDisplayName");
    const sessionFlags = await chrome.storage.session.get(["newAccountSetupAuthorized", "restoreAuthorized"]);
    let accountExists = null;
    if (validSession && navigator.onLine) {
        try {
            const startup = await fetchStartupState(owner);
            await assertStartupAuthentication(startup);
            accountExists = startup.exists;
            if (accountExists) {
                const config = startup.lock;
                const keyChanged = await LockstepVault.synchronizeWrappedKey(owner, config.wrappedKey, config.vaultRevision);
                await assertStartupAuthentication(startup);
                await chrome.storage.local.set({ cachedLockConfig: config });
                await assertStartupAuthentication(startup);
                rememberLockConfig(owner, config);
                // After a key change the next sync takes the full list (see forgetSyncCursor), not these changes.
                if (startup.entries && !keyChanged) prefetchedVault = { owner, authentication: startup.authentication, entries: startup.entries, cursor: startup.cursor, full: startup.full, deletedIds: startup.deletedIds, generation: startup.generation, localGeneration: startup.localGeneration, fetchedAt: Date.now() };
            }
        } catch (error) { if(error.code === "SESSION_CHANGED") throw error; accountExists = null; }
    }
    if (accountExists === false && !sessionFlags.newAccountSetupAuthorized) {
        await LockstepVault.clearSubject(owner); await chrome.storage.session.remove(REPLACED_VAULT_KEY);
        await chrome.storage.local.remove("cachedLockConfig");
        await chrome.storage.session.remove(["lastUnlockedAt", "unlockedMaster"]);
        lastSyncError = null;
    }
    return {
        hasSubject: true,
        displayName: refreshedClaims?.name || refreshedClaims?.given_name || refreshedClaims?.email || refreshedLocal.vaultDisplayName || local.vaultDisplayName || "",
        tokenValid: validSession,
        online: navigator.onLine,
        accountExists,
        newAccountSetupAuthorized: Boolean(sessionFlags.newAccountSetupAuthorized),
        restoreAuthorized: Boolean(sessionFlags.restoreAuthorized),
        keyState: await LockstepVault.keyState(owner),
        unlocked: LockstepVault.isUnlocked(owner),
        hasLocalEntries: (await LockstepVault.localEncryptedEntries(owner)).length > 0
    };
}

// One request for account status, lock settings and the encrypted vault. Falls back to the
// separate requests when the API has not been updated yet.
async function assertStartupAuthentication(startup) {
    if (!startup?.authentication || !await authenticationMatches(startup.authentication)) throw Object.assign(new Error("Your sign-in changed. Try again."), {code:"SESSION_CHANGED"});
}
async function fetchStartupState(owner) {
    const capturedGeneration = authenticationGeneration;
    const authentication = await authenticationSnapshot();
    if (authentication.owner !== owner || capturedGeneration !== authentication.generation) throw Object.assign(new Error("Your sign-in changed. Try again."), {code:"SESSION_CHANGED"});
    const request = (path) => api(path, {expectedAuthentication:authentication});
    assertSyncCooldown(owner);

    const generation = LockstepVault.syncGeneration(owner);
    const localGeneration = await LockstepVault.localGeneration(owner);
    if (!bootstrapUnsupported) {
        try {
            // With a cursor saved by the last sync, only the changes since then are downloaded.
            const since = await LockstepVault.startupCursor(owner);
            const startup = await request(`/api/v1/bootstrap${since == null ? "" : `?since=${encodeURIComponent(since)}`}`);
            await assertStartupAuthentication({authentication});
            await rememberServerFeatures(startup?.features);
            return { authentication, exists: Boolean(startup?.exists), lock: startup?.lock, entries: Array.isArray(startup?.entries) ? startup.entries : null, cursor: startup?.cursor ?? null,
                full: since == null || startup?.full !== false, deletedIds: Array.isArray(startup?.deletedIds) ? startup.deletedIds : [], generation, localGeneration };
        } catch (error) {
            if (error.status !== 404 && error.status !== 405) throw error;
            bootstrapUnsupported = true;
        }
    }
    const exists = Boolean((await request("/api/v1/account"))?.exists);
    return { authentication, exists, lock: exists ? await request("/api/v1/lock") : null, entries: null, cursor: null, generation };
}

async function changeStreamAuthentication() {
    const authentication = await authenticationSnapshot();
    const session = await activeAppSession();
    const {serverFeatures, cachedLockConfig:config} = await chrome.storage.local.get([SERVER_FEATURES_KEY,"cachedLockConfig"]);
    if (!await authenticationMatches(authentication)) throw coded("SESSION_CHANGED","Sign-in changed.");
    return {authentication, enabled:Boolean(config?.enabled)&&Array.isArray(serverFeatures)&&serverFeatures.includes("liveChanges"),
        url:AUTHSYNC_CONFIG.apiBaseUrl+"/api/v1/events",
        headers:{"X-Lockstep-Subject":authentication.owner,"X-Lockstep-Client":"extension","X-Lockstep-Session":session}};
}

async function checkRemoteLock() {
    const authentication = await authenticationSnapshot();
    const owner = authentication.owner;
    // No vault key yet (a passphrase is being created, or a vault is being restored): nothing to compare.
    if (await LockstepVault.keyState(owner) === "none") return false;
    if (!LockstepVault.isUnlocked(owner)) throw coded("VAULT_LOCKED", "Vault locked. Unlock it to continue.");
    assertSyncCooldown(owner);
    const latest = await api("/api/v1/lock", { expectedAuthentication: authentication });
    await applySynchronizedLock(owner, latest, authentication);
    return true;
}

async function applySynchronizedLock(owner, latest, authentication) {
    const check=async()=>{if(authentication.owner!==owner||!await authenticationMatches(authentication))throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");};
    await check();
    if(!latest)throw new Error("The server did not return vault lock settings.");
    const wasUnlocked=LockstepVault.isUnlocked(owner);
    const changed=await LockstepVault.synchronizeWrappedKey(owner,latest.wrappedKey,latest.vaultRevision);
    await writeAuthentication(async()=>{
        const revision=await LockstepVault.expectedRevision(owner);
        await check();
        if(Number.isInteger(latest.vaultRevision)&&Number.isInteger(revision)&&latest.vaultRevision<revision){
            if(wasUnlocked&&!LockstepVault.isUnlocked(owner)){
                await clearUnlockedSession(owner);
                throw coded("VAULT_LOCKED","Your vault changed on another device. Enter your current passphrase to continue.");
            }
            throw Object.assign(coded("VAULT_CHANGED","A newer vault revision is already on this device. Sync again."),{status:409});
        }
        await chrome.storage.local.set({cachedLockConfig:latest});
        rememberLockConfig(owner,latest);
    });
    if(changed&&wasUnlocked){
        await clearUnlockedSession(owner);
        throw coded("VAULT_LOCKED","Your passphrase or recovery key changed on another device. Enter your current passphrase to continue.");
    }
    if(wasUnlocked){
        await enforceTimedLock(owner);
        if(!LockstepVault.isUnlocked(owner))throw coded("VAULT_LOCKED","Your vault locked using the updated lock settings.");
        const {lastUnlockedAt}=await chrome.storage.session.get("lastUnlockedAt");
        if(lastUnlockedAt)await chrome.alarms.create("lockstep-lock",{when:lastUnlockedAt+Number(latest.timeoutSeconds)*1000});
    }
}

function transport(owner) {
    const generation = authenticationGeneration;
    const captured = authenticationSnapshot();
    const boundApi = async (path, options = {}) => {
        assertSyncCooldown(owner);
        const authentication = await captured;
        if (authentication.owner !== owner || generation !== authentication.generation || generation !== authenticationGeneration) throw Object.assign(new Error("Your sign-in changed. Try again."), {code:"SESSION_CHANGED"});
        return api(path, {...options, expectedAuthentication:authentication});
    };
    return {
        list: () => boundApi("/api/v1/entries"),
        put: (id, payload) => boundApi(`/api/v1/entries/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
        delete: (id) => boundApi(`/api/v1/entries/${id}`, { method: "DELETE" }),
        // Entries changed or deleted since a cursor (full list when since is null); null on older servers.
        changes: async (since) => {
            if(!bootstrapUnsupported){
                try {
                    const snapshot=await boundApi(`/api/v1/bootstrap${since==null?"":`?since=${encodeURIComponent(since)}`}`);
                    if(!snapshot.exists)throw coded("ACCOUNT_MISSING","Your server account no longer exists. Sign in again to start fresh.");
                    await applySynchronizedLock(owner,snapshot.lock,await captured);
                    return snapshot;
                } catch(error) {
                    if(error.status!==404&&error.status!==405)throw error;
                    bootstrapUnsupported=true;
                }
            }
            if (changesUnsupported) return null;
            try { return await boundApi(`/api/v1/entries/changes${since == null ? "" : `?since=${encodeURIComponent(since)}`}`); }
            catch (error) {
                if (error.status !== 404 && error.status !== 405) throw error;
                changesUnsupported = true;
                return null;
            }
        },
        batch: async (operations) => {
            if (batchUnsupported) return null;
            try { return await boundApi("/api/v1/entries/batch", { method: "POST", body: JSON.stringify({ operations }) }); }
            catch (error) {
                if (error.status !== 404 && error.status !== 405) throw error;
                batchUnsupported = true;
                return null;
            }
        }
    };
}

// Set while this device keeps an older vault after the server's vault was replaced (see verifyLock): nothing
// is exchanged with the server then. Kept in session storage so a worker restart does not forget it.
const REPLACED_VAULT_KEY = "replacedVaultOwner";
async function keepsReplacedVault(owner) {
    try { return (await chrome.storage.session.get(REPLACED_VAULT_KEY))[REPLACED_VAULT_KEY] === owner; } catch { return false; }
}

async function synchronize(allowLockedPull = false) {
    const owner = await subject();
    const authentication=await authenticationSnapshot();
    const checkAuthentication=async()=>{if(authentication.owner!==owner||!await authenticationMatches(authentication))throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");};
    await checkAuthentication();
    if (await keepsReplacedVault(owner)) return { pending: 0, replaced: true };
    try {
        if(!LockstepVault.isUnlocked(owner)&&!allowLockedPull){
            const result=await LockstepVault.synchronize(owner,transport(owner),false);
            await rememberSyncNotice(result.notice);
            lastSyncError=null;syncRetryStates.delete(owner);
            if(result.pending)await schedulePendingSync(TRANSIENT_RETRY_MIN_MILLIS);else await stopPendingSync();
            return result;
        }
        // Right after the popup's startup request the account is known to exist and the vault list is fresh.
        if (startupInFlight) await startupInFlight;
        const prefetched = takePrefetchedVault(owner);
        if (!prefetched) {
            assertSyncCooldown(owner);
            if (!await backendAccountExists(authentication)) throw coded("ACCOUNT_MISSING", "Your server account no longer exists. Sign in again to start fresh.");
            if(bootstrapUnsupported){
                const latest=await api("/api/v1/lock",{expectedAuthentication:authentication});
                await applySynchronizedLock(owner,latest,authentication);
            }
        }
        const result = await LockstepVault.synchronize(owner, transport(owner),allowLockedPull,prefetched);
        await rememberSyncNotice(result.notice);
        lastSyncError = null;syncRetryStates.delete(owner);syncRetryAt = 0;
        if(result.pending)await schedulePendingSync(TRANSIENT_RETRY_MIN_MILLIS);else await stopPendingSync();
        // Entries saved by older versions still have readable names on the server: re-save them encrypted.
        if (LockstepVault.isUnlocked(owner) && await LockstepVault.sealPlaintextLabels(owner).catch(() => 0)) await schedulePendingSync(0);
        return result;
    } catch (error) {
        await rememberSyncNotice(error?.notice); // a refused change was dropped before a later step failed
        lastSyncError = error?.message || "Lockstep could not sync. It will try again.";
        noteSyncFailure(owner, error);
        if(await LockstepVault.pendingCount(owner))await schedulePendingSync(TRANSIENT_RETRY_MIN_MILLIS);
        throw error;
    }
}

async function localEntries() {
    return LockstepVault.listEntries(await subject());
}

async function listEntries() {
    await synchronize().catch(() => null);
    return localEntries();
}

async function addOtpUri(otpAuthUri) {
    const owner = await subject();
    const entry = await LockstepVault.addOtpUri(owner, otpAuthUri);
    await synchronize().catch(() => null);
    return entry;
}

async function updateEntry(id, issuer, accountName) {
    const owner = await subject();
    const entry = await LockstepVault.updateEntry(owner, id, issuer, accountName);
    await synchronize().catch(() => null);
    return entry;
}

async function deleteEntry(id, passcode) {
    const owner = await subject(), epoch = lockEpoch;
    if (!await LockstepVault.exportWrappedKey(owner)) throw new Error("Set up your vault passphrase before removing accounts.");
    await requireExportPassphrase(passcode);
    await ensureRecentGoogleSignIn();
    const check = async () => { if (lockEpoch !== epoch || !LockstepVault.isUnlocked(owner) || owner !== await subject()) throw coded("VAULT_LOCKED", "Vault locked. Unlock it to continue."); };
    await check();
    await LockstepVault.flushOutbox(owner, transport(owner));
    await check();
    await api(`/api/v1/entries/${id}`, { method: "DELETE" });
    await LockstepVault.acceptServerDeletion(owner, id);
    return null;
}

async function importEntries(otpAuthUris) {
    if (!Array.isArray(otpAuthUris) || otpAuthUris.length === 0 || otpAuthUris.length > 1000) {
        throw new Error("Choose a valid Lockstep backup containing 1 to 1000 entries.");
    }
    const authentication=await authenticationSnapshot();
    const owner=authentication.owner;
    let imported=0,failed=0;
    const check=async()=>{
        if(authenticationTransition || !await authenticationMatches(authentication))throw coded("SESSION_CHANGED","Your sign-in changed. Import stopped.");
        if(!LockstepVault.isUnlocked(owner))throw coded("VAULT_LOCKED","Vault locked. Import stopped.");
    };
    try {
        for(const uri of otpAuthUris){
            await check();
            try {await LockstepVault.addOtpUri(owner,uri);imported++;}
            catch(error){
                if(["VAULT_LOCKED","SESSION_CHANGED","SESSION_EXPIRED","SESSION_REVOKED"].includes(error.code))throw error;
                failed++;
            }
            await check();
        }
        await check();
        await synchronize().catch(error=>{if(error.code==="SESSION_CHANGED"||error.code==="VAULT_LOCKED")throw error;});
        await check();
    }catch(error){
        error.message+=` ${imported} account${imported===1?" was":"s were"} imported into the original vault before stopping; ${failed} failed.`;
        throw error;
    }
    return {imported,failed};
}

// Exports need the vault passphrase again (checked here, on this device), so someone at an unlocked,
// unattended browser cannot walk away with every secret. With a backup password the file is encrypted.
async function requireExportPassphrase(passcode) {
    if (!await LockstepVault.checkPassphrase(await subject(), passcode)) throw coded("WRONG_PASSKEY", "Incorrect passphrase.");
}
async function exportEntries(passcode, backupPassword) {
    await requireExportPassphrase(passcode);
    const text = await LockstepVault.exportText(await subject());
    return backupPassword ? LockstepVault.encryptBackup(text, backupPassword) : text;
}
async function localOtpUri(id) { return LockstepVault.otpAuthUri(await subject(), id); }
async function exportRecoveryKey(passcode) {
    await requireExportPassphrase(passcode);
    const owner = await subject();
    if (navigator.onLine&&await activeAppSession().then(()=>true).catch(()=>false)) {
        const config = await api("/api/v1/lock");
        const changed = await LockstepVault.synchronizeWrappedKey(owner, config.wrappedKey, config.vaultRevision);
        await chrome.storage.local.set({ cachedLockConfig: config });
        if (changed) throw coded("VAULT_LOCKED", "Your passphrase changed on another device. Unlock again before downloading the recovery key.");
    }
    return LockstepVault.exportRecoveryKey(owner);
}
async function importRecoveryKey(value, passcode) {
    const epoch=lockEpoch,generation=authenticationGeneration;
    const check=()=>{if(epoch!==lockEpoch || generation!==authenticationGeneration)throw coded("VAULT_LOCKED","Vault locked. Unlock it to continue.");};
    await activeAppSession(); // fail before touching local state if the 30-day session ended
    await ensureServerFeatures();
    const owner = await subject();
    if ((await chrome.storage.local.get("cachedLockConfig")).cachedLockConfig?.wrappedKey) await ensureRecentGoogleSignIn();
    await synchronize(true); // restoration is the explicit locked flow allowed to download ciphertext for key verification
    check();
    const version = await LockstepVault.importRecoveryKey(owner, value, passcode);
    check();
    const cached = (await chrome.storage.local.get("cachedLockConfig")).cachedLockConfig;
    const wrappedKey = await LockstepVault.exportWrappedKey(owner);
    const expectedRevision = await LockstepVault.expectedRevision(owner);
    const config = await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ timeoutSeconds: cached?.timeoutSeconds || 300, lockOnScreenLock:Boolean(cached?.lockOnScreenLock), wrappedKey, expectedRevision }) });
    check();
    await LockstepVault.markWrappedKeySynced(owner, config?.vaultRevision, config?.wrappedKey);
    check();
    await chrome.storage.local.set({ cachedLockConfig: config });
    await chrome.storage.session.remove("restoreAuthorized");
    await persistUnlockedSession(owner, config);
    check();
    return { version, entries: await localEntries() };
}
// The server's vault was replaced outside Lockstep (see LockstepVault.serverVaultReplaced): take the server's
// key when nothing would be lost. Returns true when adopted (the vault must be unlocked again with the
// server's passphrase); throws the reason when this device still holds something the server does not.
async function adoptReplacedServerVault(owner, lock) {
    if (!await LockstepVault.serverVaultReplaced(owner, lock?.wrappedKey, lock?.vaultRevision)) return false;
    const serverEntries = await api("/api/v1/entries");
    return LockstepVault.adoptReplacedServerVault(owner, lock.wrappedKey, lock.vaultRevision, serverEntries.map((entry) => entry.id));
}

// The user chose the server's vault (after unlocking reported VAULT_REPLACED): remove this device's copy of
// the older vault, take the server's key, and unlock it with the passphrase (the server's may differ).
async function adoptServerVaultNow(passcode) {
    const owner = await subject();
    await activeAppSession();
    const latest = await api("/api/v1/lock");
    if (await LockstepVault.serverVaultReplaced(owner, latest.wrappedKey, latest.vaultRevision)) {
        await LockstepVault.adoptReplacedServerVault(owner, latest.wrappedKey, latest.vaultRevision, [], { force: true });
        await chrome.storage.local.set({ cachedLockConfig: latest });
        rememberLockConfig(owner, latest);
    }
    await clearUnlockedSession(owner);
    return verifyLock(passcode);
}

async function rotateEncryptionKey(passcode) {
    await activeAppSession(); // rotation needs a live session: the server must accept the new key
    await ensureRecentGoogleSignIn();
    const owner = await subject();
    await ensureServerFeatures();
    // Verify against fresh metadata even if another device changed the key since the last sync.
    const latest = await api("/api/v1/lock");
    let keyChanged;
    try { keyChanged = await LockstepVault.refreshRotationKey(owner, latest.wrappedKey, latest.vaultRevision, passcode); }
    catch (error) {
        // A different key on the server: if its vault replaced this device's older one, take it (unless that
        // would lose accounts or changes that only this device has), then continue.
        if (error.code !== "VAULT_STATE_MISMATCH") throw error;
        try { if (!await adoptReplacedServerVault(owner, latest)) throw error; }
        catch (adoptError) {
            if (adoptError.code === "VAULT_REPLACED") throw coded("VAULT_REPLACED", `${adoptError.message} Lock and unlock Lockstep to choose what to do with them before rotating.`);
            throw adoptError;
        }
        keyChanged = true;
    }
    if (keyChanged) {
        try { await LockstepVault.unlock(owner, passcode); }
        catch (error) { await clearUnlockedSession(owner); throw error; }
    }
    await chrome.storage.local.set({ cachedLockConfig: latest });
    rememberLockConfig(owner, latest);
    await synchronize(); // fully synced before the key changes
    // 1. Re-encrypt everything in memory only (refuses while changes are still pending). Until step 3 (or a
    //    failure), no other change can be made on this device.
    const prepared = await LockstepVault.prepareMasterRotation(owner, passcode);
    // 2. The server swaps the wrapped key and every entry in one transaction, or refuses if the vault changed.
    let response;
    try {
        const cached = (await chrome.storage.local.get("cachedLockConfig")).cachedLockConfig;
        response = await api("/api/v1/vault/rotate", { method: "POST", body: JSON.stringify({
            timeoutSeconds: cached?.timeoutSeconds || 300, lockOnScreenLock: Boolean(cached?.lockOnScreenLock),
            wrappedKey: prepared.wrappedKey, entries: prepared.entries.map(entry => ({ id: entry.id, entry })), previous: prepared.previous,
            expectedRevision: prepared.expectedRevision }) });
    } catch (error) {
        LockstepVault.cancelMasterRotation(prepared); // this device keeps its current key
        if (error.status === 404 || error.status === 405) throw new Error("Update the Lockstep server before rotating the recovery key.");
        if (error.status === 409 || error.status === 400 || error.status === 413 || error.status === 429) throw error; // refused: nothing changed anywhere
        throw coded(error.code || "ROTATION_UNCONFIRMED", `The rotation could not be confirmed (${error.message}). If it went through, this device picks up the new key the next time you unlock; then download your recovery key from Settings.`);
    }
    // 3. Only now store the new key and entries on this device.
    const result = await LockstepVault.commitMasterRotation(prepared, response.entries, response.lock?.vaultRevision);
    await chrome.storage.local.set({ cachedLockConfig: response.lock });
    rememberLockConfig(owner, response.lock);
    await persistUnlockedSession(owner, response.lock);
    return { version: result.version, count: result.count, recoveryKey: result.recoveryKey, rotated: true, synchronized: true };
}
async function syncState() {
    const { syncNotice } = await chrome.storage.session.get("syncNotice").catch(() => ({}));
    if (syncNotice) await chrome.storage.session.remove("syncNotice").catch(() => {});
    return { online: await checkConnectivity(), pending: await LockstepVault.pendingCount(await subject()), error: lastSyncError, notice: syncNotice || null,
        retryInMillis: lastSyncError && syncRetryAt ? Math.max(0, syncRetryAt - Date.now()) : null };
}

// Re-protects a PBKDF2 vault with Argon2id after the user agreed. Saving the re-wrapped key replaces the one
// other devices use, so it needs a Google sign-in the user completed (REAUTH_REQUIRED asks for it).
async function upgradeProtection(passcode) {
    const owner = await subject();
    await activeAppSession();
    await ensureServerFeatures();
    if (!await LockstepVault.needsWrappingUpgrade(owner, passcode)) return { upgraded: false };
    await ensureRecentGoogleSignIn();
    if (!await LockstepVault.upgradeWrapping(owner, passcode)) return { upgraded: false };
    const pending = await LockstepVault.pendingWrappedKeyUpload(owner);
    if (!pending) return { upgraded: false };
    const cached = await cachedLockConfig();
    let config;
    try {
        config = await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ timeoutSeconds: cached.timeoutSeconds || 300, lockOnScreenLock: Boolean(cached.lockOnScreenLock), wrappedKey: pending.wrappedKey, expectedRevision: pending.expectedRevision }) });
    } catch (error) {
        if (error.status === 409 && await adoptServerKeyAfterConflict(owner)) throw coded("VAULT_LOCKED", error.message);
        throw error;
    }
    await LockstepVault.markWrappedKeySynced(owner, config?.vaultRevision, config?.wrappedKey);
    await chrome.storage.local.set({ cachedLockConfig: config });
    rememberLockConfig(owner, config);
    await persistUnlockedSession(owner, config);
    return { upgraded: true };
}

async function registerAppSession() {
    const generation=authenticationGeneration;
    const response=await fetch(AUTHSYNC_CONFIG.apiBaseUrl+"/api/v1/session",{
        method:"POST",cache:"no-store",signal:AbortSignal.timeout(45000),
        headers:{"Content-Type":"application/json",Authorization:`Bearer ${await token()}`,"X-Lockstep-Client":"extension"}
    });
    const body=await response.json().catch(()=>({}));
    if(!response.ok||!body.sessionToken){
        throw coded(body.code||(response.status===401?"SESSION_EXPIRED":"REQUEST_FAILED"),body.error||(response.status===401?"Session expired. Sign in with Google again.":`Lockstep could not complete the request (error ${response.status}). Try again.`));
    }
    await writeAuthentication(async()=>{
        if(generation!==authenticationGeneration)throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
        await chrome.storage.local.set({appSessionId:body.sessionToken,appSessionExpiry:Number(body.expiresAtEpochMillis)||0});
        authenticationTransition=false;
    });
    return body.sessionToken;
}

async function appSession() {
    if(authenticationTransition)throw coded("SESSION_CHANGED","Sign-in is in progress. Try again in a moment.");
    const authentication=await authenticationSnapshot();
    const stored=await chrome.storage.local.get(["appSessionId","appSessionExpiry"]);
    if(stored.appSessionId&&Number(stored.appSessionExpiry)>Date.now())return stored.appSessionId;
    if(stored.appSessionId){
        const error=coded("SESSION_EXPIRED","Your 30-day Lockstep session has expired. Sign in with Google again.");
        if(!await invalidateAuthentication(error.message,authentication))throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
        throw error;
    }
    throw coded("SESSION_EXPIRED","Sign in with Google first.");
}

async function activeAppSession(){return appSession();}

async function checkConnectivity() {
    return navigator.onLine;
}

async function checkActiveSession() {
    const controller=new AbortController();
    const timeout=setTimeout(()=>controller.abort(),5000);
    try{
        const local=await chrome.storage.local.get("vaultSubject");
        if(!local.vaultSubject)return false;
        await activeAppSession();
        if(!navigator.onLine)return false;
        await api("/api/v1/session",{signal:controller.signal});
        return true;
    }catch(error){if(error?.code==="SESSION_REVOKED"||error?.code==="SESSION_EXPIRED")throw error;return false;}
    finally{clearTimeout(timeout);}
}

function scheduleConnectivityCheck() {
    clearTimeout(connectivityTimeout);
    connectivityTimeout=setTimeout(()=>pollConnectivity().catch(()=>null),BACKGROUND_CHECK_MILLIS);
    chrome.alarms.create(CONNECTIVITY_ALARM,{when:Date.now()+BACKGROUND_CHECK_MILLIS});
}

async function pollConnectivity() {
    if(connectivityPollPromise)return connectivityPollPromise;
    connectivityPollPromise=(async()=>{
        clearTimeout(connectivityTimeout);connectivityTimeout=null;
        try{await checkActiveSession();}finally{scheduleConnectivityCheck();}
    })().finally(()=>{connectivityPollPromise=null;});
    return connectivityPollPromise;
}

async function getLockConfig() {
    const owner = await subject();
    const keyState = await LockstepVault.keyState(owner);
    let config;
    try {
        // Opening the popup asks for the lock settings several times within a second; reuse the
        // answer read moments ago instead of repeating the request.
        config = recentLock(owner);
        if (!config) {
            config = await api("/api/v1/lock");
            await LockstepVault.synchronizeWrappedKey(owner, config.wrappedKey, config.vaultRevision);
            await chrome.storage.local.set({ cachedLockConfig: config });
            rememberLockConfig(owner, config);
        }
    } catch (error) {
        const cached = await chrome.storage.local.get("cachedLockConfig");
        config = cached.cachedLockConfig;
        // Offline / expired token but this device holds a protected key: the lock obviously exists.
        if (!config && keyState === "wrapped") config = { enabled: true, timeoutSeconds: 300, lockOnScreenLock:false };
        // Nothing known on this device: report what actually failed. Only a refused or expired session means
        // "sign in again" (api() has already signed out for those); a server that is briefly unreachable does not.
        if (!config) throw error?.code ? error : coded("BACKEND_UNAVAILABLE", "Can't reach Lockstep. Check your internet connection and try again.");
    }
    // A passkey-wrapped key on this device means the lock is on, whatever a stale cache/server says.
    if (keyState === "wrapped" && !config.enabled) config = { ...config, enabled: true };
    const timeout=Number(config.timeoutSeconds);
    config = { ...config, timeoutSeconds: ALLOWED_LOCK_TIMEOUTS.has(timeout) ? timeout : 300, lockOnScreenLock:Boolean(config.lockOnScreenLock) };
    return config;
}
async function setLockConfig(passcode, timeoutSeconds, lockOnScreenLock, initialSetup = false) {
    const vaultSubject = await subject();
    await activeAppSession(); // SESSION_EXPIRED up front, before any local key material changes
    await ensureServerFeatures();
    let config;
    if (initialSetup) {
        // Never mint a new master key if the server already holds ciphertext we cannot decrypt
        // (reset laptop / cleared IndexedDB): that would orphan the whole vault.
        await synchronize().catch(() => null);
        if (await LockstepVault.keyState(vaultSubject) === "none" && (await LockstepVault.localEncryptedEntries(vaultSubject)).length > 0) {
            throw coded("KEY_MISSING", "This device does not have your vault key. Restore it with your recovery key.");
        }
        await LockstepVault.configurePassphrase(vaultSubject, passcode);
    } else {
        // Changing an existing passphrase replaces the key other devices use: confirm with Google first.
        await ensureRecentGoogleSignIn();
        // The vault may have locked meanwhile (for example the passphrase was changed on another device). Changing
        // it now would be treated as a first-time setup, so stop with the same message as other locked actions.
        if (!LockstepVault.isUnlocked(vaultSubject)) throw coded("VAULT_LOCKED", "Vault locked. Unlock it to continue.");
        await LockstepVault.configurePassphrase(vaultSubject, passcode);
    }
    const wrappedKey = await LockstepVault.exportWrappedKey(vaultSubject);
    const expectedRevision = await LockstepVault.expectedRevision(vaultSubject);
    try {
        config = await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ timeoutSeconds, lockOnScreenLock:Boolean(lockOnScreenLock), wrappedKey, expectedRevision }) });
    } catch (error) {
        // Another device changed the passphrase or rotated the key meanwhile: take its key, do not overwrite it.
        if (error.status === 409 && await adoptServerKeyAfterConflict(vaultSubject)) throw coded("VAULT_LOCKED", error.message);
        throw error;
    }
    await LockstepVault.markWrappedKeySynced(vaultSubject, config?.vaultRevision, config?.wrappedKey);
    await chrome.storage.local.set({ cachedLockConfig: config });
    await chrome.storage.session.remove("newAccountSetupAuthorized");
    await persistUnlockedSession(vaultSubject, config);
    await ensureDeviceLockWatch();
    if (!initialSetup) return config;
    return { ...config, recoveryKey: await LockstepVault.exportRecoveryKey(vaultSubject) };
}
// After the server refused a key change (409): load its wrapped key. Returns true when this device's key was
// replaced; the vault is then locked and opens with the current passphrase.
async function adoptServerKeyAfterConflict(owner) {
    try {
        const latest = await api("/api/v1/lock");
        if (!await LockstepVault.synchronizeWrappedKey(owner, latest.wrappedKey, latest.vaultRevision)) return false;
        await chrome.storage.local.set({ cachedLockConfig: latest });
        rememberLockConfig(owner, latest);
        await clearUnlockedSession(owner);
        return true;
    } catch { return false; }
}

async function verifyLock(passcode) {
    unlocksInProgress++;
    try { return await verifyLockNow(passcode); }
    finally { unlocksInProgress--; }
}
async function verifyLockNow(passcode) {
    const owner = await subject();
    const epoch = lockEpoch;
    const lockedMeanwhile = async () => {
        if (lockEpoch === epoch) return;
        LockstepVault.lock(owner);
        await chrome.storage.session.remove(["lastUnlockedAt", "unlockedMaster"]);
        throw coded("VAULT_LOCKED", "Vault locked. Unlock it to continue.");
    };
    let serverAvailable = false;
    let serverWrappedKey = null;
    let replacedNotice = null;
    await chrome.storage.session.remove(REPLACED_VAULT_KEY);
    if (navigator.onLine&&await activeAppSession().then(()=>true).catch(()=>false)) {
        try {
            const latest = await api("/api/v1/lock");
            serverWrappedKey = latest.wrappedKey || null;
            await LockstepVault.synchronizeWrappedKey(owner, latest.wrappedKey, latest.vaultRevision);
            // The server's vault was replaced outside Lockstep: take its key now when nothing would be lost;
            // otherwise keep this device's key (nothing is uploaded) so its accounts can still be exported.
            try { await adoptReplacedServerVault(owner, latest); }
            catch (error) { if (error.code !== "VAULT_REPLACED") throw error; replacedNotice = error.message; }
            await chrome.storage.local.set({ cachedLockConfig: latest });
            serverAvailable = !replacedNotice;
        } catch { /* The local passphrase remains authoritative while offline. */ }
    }
    const keyState = await LockstepVault.keyState(owner);
    if (keyState === "none") {
        // No key on this device (reset / cleared storage). A correct passphrase cannot help; need recovery key.
        if (!serverAvailable) throw coded("SESSION_EXPIRED", "Sign in again to restore your vault.");
        throw coded("KEY_MISSING", "This device does not have your vault key. Restore it with your recovery key.");
    }
    try {
        // Local AES-GCM unwrap is authoritative and works offline / with an expired Google token.
        await LockstepVault.unlock(owner, passcode);
        await lockedMeanwhile();
        // Record the unlock at once: a popup refresh arriving during the server checks below must not see an
        // unlocked vault without an unlock time and lock it again (it is recorded once more at the end).
        await persistUnlockedSession(owner);
        // Accounts added offline before the recovery key was rotated elsewhere: re-encrypt them with the new key.
        const rescued = replacedNotice ? 0 : await LockstepVault.rescueStrandedEntries(owner, passcode).catch(() => 0);
        if (rescued) void schedulePendingSync(0);
        // With Argon2id switched on, re-protect a PBKDF2 vault when a recent Google sign-in allows saving it.
        await serverFeaturesRestored;
        if (serverAvailable && await ensureRecentGoogleSignIn({ interactive: false }).catch(() => false)) {
            await LockstepVault.upgradeWrapping(owner, passcode).catch(() => false);
        }
        if (serverAvailable) {
            // Firestore may have been manually cleared while this device retained its
            // wrapped master key. Republish the lock settings and wrapped key (never the passphrase)
            // before entries synchronize.
            const serverConfig = await api("/api/v1/lock");
            const hasRevision = Number.isInteger(serverConfig.vaultRevision);
            // Current servers: upload a passphrase change or recovery-key import saved here but not yet on the
            // server, expecting the revision it was based on; if another device changed the key since, the server
            // refuses and this device takes the server's key (it never overwrites it). Older servers: the previous
            // rule (the newer wrapped key wins) still applies.
            const pending = hasRevision ? await LockstepVault.pendingWrappedKeyUpload(owner) : null;
            const localWrapped = await LockstepVault.exportWrappedKey(owner);
            const localNewer = !hasRevision && Number(localWrapped?.wrappedAt || localWrapped?.createdAt || 0) > Number(serverConfig.wrappedKey?.wrappedAt || serverConfig.wrappedKey?.createdAt || 0);
            if (!serverConfig.enabled || localNewer || pending) {
                const cached = await chrome.storage.local.get("cachedLockConfig");
                const timeoutSeconds = cached.cachedLockConfig?.timeoutSeconds || 300;
                const expectedRevision = pending ? pending.expectedRevision : hasRevision ? serverConfig.vaultRevision : undefined;
                try {
                    const restored = await api("/api/v1/lock", {
                        method: "PUT",
                        body: JSON.stringify({ timeoutSeconds, lockOnScreenLock:Boolean(cached.cachedLockConfig?.lockOnScreenLock), wrappedKey: await LockstepVault.exportWrappedKey(owner), expectedRevision })
                    });
                    await LockstepVault.markWrappedKeySynced(owner, restored?.vaultRevision, restored?.wrappedKey);
                    await chrome.storage.local.set({ cachedLockConfig: restored });
                } catch (error) {
                    if (error.status === 409) {
                        if (await adoptServerKeyAfterConflict(owner)) {
                            throw coded("PASSPHRASE_CHANGED", "Your passphrase was changed on another device. Unlock with the current passphrase.");
                        }
                        // The server already has this device's key (a parallel request saved it first): nothing
                        // is left to upload, so the unlock stands. Like the web app.
                        if (await LockstepVault.pendingWrappedKeyUpload(owner)) throw error;
                    } else if (error.code !== "REAUTH_REQUIRED") {
                        // Saving a changed key needs a recent Google sign-in; without one it stays on this device
                        // and is uploaded on a later unlock.
                        throw error;
                    }
                }
            }
        }
        if (replacedNotice) await chrome.storage.session.set({ [REPLACED_VAULT_KEY]: owner });
        await persistUnlockedSession(owner, await cachedLockConfig());
        // Locked while this unlock was still running (Lock button, timeout, screen lock): the lock wins.
        await lockedMeanwhile();
        if (!LockstepVault.isUnlocked(owner)) throw coded("VAULT_LOCKED", "Vault locked. Unlock it to continue.");
        await ensureDeviceLockWatch();
        // The popup asks whether to switch to the server's vault (ADOPT_SERVER_VAULT) or keep this one for now.
        if (replacedNotice) return { unlocked: true, replaced: replacedNotice };
        // A PBKDF2 vault that could not be upgraded silently: the popup offers the upgrade (UPGRADE_PROTECTION).
        const upgradeAvailable = serverAvailable && await LockstepVault.needsWrappingUpgrade(owner, passcode).catch(() => false);
        return { unlocked: true, ...(upgradeAvailable ? { upgradeAvailable: true } : {}), ...(rescued ? { rescued } : {}) };
    } catch (error) {
        if (error.code !== "WRONG_PASSKEY" || !serverAvailable) throw error;
        // Local passphrase wrong. If it opens the server's wrapped key instead, the passphrase was changed on
        // another device. Checked locally, so the passphrase never leaves this device.
        if (serverWrappedKey && await LockstepVault.passkeyOpensWrappedKey(owner, serverWrappedKey, passcode).catch(() => false)) {
            throw coded("NEEDS_RECOVERY", "Your passphrase was changed on another device. Enter your recovery key to update this one.");
        }
        throw error;
    }
}
async function lockVault() {
    const owner=await subject();
    await clearUnlockedSession(owner, true);
}
async function resetVault(passcode) {
    const owner = await subject();
    await activeAppSession();
    await ensureRecentGoogleSignIn();
    if (!await LockstepVault.exportWrappedKey(owner)) throw new Error("Open this vault on this device before resetting it.");
    await requireExportPassphrase(passcode);
    if (owner !== await subject()) throw coded("SESSION_EXPIRED", "Sign in again before resetting this vault.");
    await api("/api/v1/vault", { method: "DELETE" });
    await LockstepVault.clearSubject(owner); await chrome.storage.session.remove(REPLACED_VAULT_KEY);
    await chrome.storage.local.remove("cachedLockConfig");
    await chrome.storage.session.remove("lastUnlockedAt");
    await chrome.storage.session.remove("restoreAuthorized");
    return true;
}
async function removeLock() {
    throw new Error("The passphrase can't be turned off because it protects your accounts. You can change it instead.");
}

const syncRetryStates = new Map();
const TRANSIENT_RETRY_MIN_MILLIS = 5000, TRANSIENT_RETRY_MAX_MILLIS = 10000;
function assertSyncCooldown(owner) {
    const remaining = retryDelay(owner);
    if (remaining > 0) throw Object.assign(new Error("Sync is waiting before retrying. Your changes are kept on this device."), {code:"SYNC_COOLDOWN", retryAfterMillis:remaining});
}
function resetNetworkBackoff() {
    for(const [owner,retry] of syncRetryStates) {
        if(retry.serverUntil>Date.now())syncRetryStates.set(owner,{failures:0,serverUntil:retry.serverUntil,until:retry.serverUntil});
        else syncRetryStates.delete(owner);
    }
}
function retryDelay(owner) { return Math.max(0, (syncRetryStates.get(owner)?.until || 0) - Date.now()); }
function recordSyncFailure(owner, error) {
    if (!owner || error.code === "SESSION_CHANGED" || error.code === "VAULT_LOCKED") return;
    const failures = Math.min(6, (syncRetryStates.get(owner)?.failures || 0) + 1);
    // Transient failures (no connection to Lockstep, a timeout, a server error) are retried every 5 to 10 seconds
    // (random, so devices do not retry in lockstep). An explicit Retry-After from the server always wins.
    const delay = Math.max(error.retryAfterMillis || 0, TRANSIENT_RETRY_MIN_MILLIS + Math.random() * (TRANSIENT_RETRY_MAX_MILLIS - TRANSIENT_RETRY_MIN_MILLIS));
    const serverUntil=Math.max(syncRetryStates.get(owner)?.serverUntil || 0, Date.now() + (error.retryAfterMillis || 0));
    syncRetryStates.set(owner, {failures, serverUntil, until:Math.max(syncRetryStates.get(owner)?.until || 0, Date.now() + delay)});
}
function retryAfterMillis(response) {
    const value = response.headers?.get?.("Retry-After");
    if (!value) return 0;
    const seconds = Number(value);
    return Math.max(0, Number.isFinite(seconds) ? seconds * 1000 : (Date.parse(value) || 0) - Date.now());
}
async function api(path, options = {}) {
    const owner = options.expectedAuthentication?.owner || await subject().catch(()=>null);
    try { return await apiRequest(path, options); }
    catch (error) {
        if (error?.name === "TimeoutError" || error?.name === "AbortError" && !options.signal?.aborted) {
            error = Object.assign(new Error("Lockstep took too long to respond. Your change may still have reached the server; sync will retry safely."), {code:"BACKEND_UNAVAILABLE"});
        }
        if(error.code === "BACKEND_UNAVAILABLE" || error.status === 429 || error.status >= 500 || error instanceof TypeError) recordSyncFailure(owner,error);
        throw error;
    }
}

async function apiRequest(path, options = {}) {
    if(authenticationTransition)throw coded("SESSION_CHANGED","Sign-in is in progress. Try again in a moment.");
    const authentication=options.expectedAuthentication || await authenticationSnapshot();
    if(!await authenticationMatches(authentication))throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
    const sessionToken=await appSession();
    // Ordinary requests use the 30-day Lockstep session. A Google token is added only while the stored one
    // is still valid; no hidden Google sign-in is attempted per request. Actions that need a recent Google
    // sign-in get one first through ensureRecentGoogleSignIn.
    const googleToken=await validStoredGoogleToken();
    const owner=await subject();
    const headers={ "Content-Type":"application/json", ...(googleToken?{Authorization:`Bearer ${googleToken}`}:{"X-Lockstep-Subject":owner}), "X-Lockstep-Client":"extension", "X-Lockstep-Session":sessionToken, ...options.headers };
    if(!await authenticationMatches(authentication))throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
    // Any change on the server makes the remembered lock settings and vault list stale.
    if ((options.method || "GET").toUpperCase() !== "GET") forgetRecentReads();
    let response;
    try{
        response=await fetch(AUTHSYNC_CONFIG.apiBaseUrl+path,{...options,cache:"no-store",headers,signal:options.signal?AbortSignal.any([options.signal,AbortSignal.timeout(45000)]):AbortSignal.timeout(45000)});
    }catch(error){
        if(error?.name === "TimeoutError" || error?.name === "AbortError") throw error;
        throw coded("BACKEND_UNAVAILABLE","Can't reach Lockstep. Check your internet connection and try again.");
    }
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        const error=coded(body.code||(response.status===401?"SESSION_EXPIRED":"REQUEST_FAILED"),body.error||(response.status===401?"Session expired. Sign in with Google again.":`Lockstep could not complete the request (error ${response.status}). Try again.`));
        error.status=response.status;error.retryAfterMillis=retryAfterMillis(response);
        if(error.code==="SESSION_REVOKED"||error.code==="SESSION_EXPIRED") {
            if(!await invalidateAuthentication(error.message,authentication))throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
        }
        throw error;
    }
    const result=response.status===204?null:await response.json();
    if(!await authenticationMatches(authentication))throw coded("SESSION_CHANGED","Your sign-in changed. Try again.");
    return result;
}

async function startScan() {
    await subject();
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error("Open the webpage containing the QR code, then scan again.");
    assertScannableTab(tab.url);
    try {
        const screenshot = await chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" });
        await chrome.scripting.executeScript({ target: { tabId: tab.id }, files: ["vendor/jsQR.js", "scanner.js"] });
        await chrome.tabs.sendMessage(tab.id, { type: "AUTHSYNC_SELECT_QR", screenshot });
        activeScannerTabId=tab.id;
        await chrome.storage.session.set({activeScannerTabId:tab.id});
    } catch (error) {
        if (/cannot access|cannot be scripted|missing host permission/i.test(error.message)) {
            throw new Error("This page is protected by Chrome. Open the webpage containing the QR code, then scan again.");
        }
        throw error;
    }
    return null;
}

function assertScannableTab(tabUrl) {
    let url;
    try { url = new URL(tabUrl); } catch { throw new Error("Open the webpage containing the QR code, then scan again."); }
    const protectedStore = url.hostname === "chromewebstore.google.com" || url.hostname === "chrome.google.com" && url.pathname.startsWith("/webstore");
    if (!["http:", "https:"].includes(url.protocol) || protectedStore) {
        throw new Error("This page is protected by Chrome. Open the webpage containing the QR code, then scan again.");
    }
}

function parseClaims(jwt) {
    const base64 = jwt.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    return JSON.parse(decodeURIComponent(atob(base64).split("").map(character => `%${character.charCodeAt(0).toString(16).padStart(2, "0")}`).join("")));
}

async function enforceDeviceScreenLock(deviceState = null) {
    const state=deviceState||await chrome.idle.queryState(15);
    if(state!=="locked")return false;
    const config=await cachedLockConfig();
    if(!config.enabled||!config.lockOnScreenLock)return false;
    let owner;try{owner=await subject();}catch{return false;}
    await clearUnlockedSession(owner, true);
    return true;
}

async function enforceDeviceSuspendLock(alarm = null) {
    const config=await cachedLockConfig();
    if(!config.enabled||!config.lockOnScreenLock)return false;
    const state=await chrome.idle.queryState(15);
    const resumedAfterSuspend=Boolean(alarm?.scheduledTime)&&Date.now()-alarm.scheduledTime>DEVICE_SUSPEND_GRACE_MS;
    if(state!=="locked"&&!resumedAfterSuspend)return false;
    let owner;try{owner=await subject();}catch{return false;}
    await clearUnlockedSession(owner, true);
    return true;
}

// The 30-second check (it notices a device that slept) runs only while it can matter: "lock when the screen
// locks" is on. Otherwise the worker is not woken up for it.
async function ensureDeviceLockWatch() {
    chrome.idle.setDetectionInterval(15);
    const config=await cachedLockConfig();
    if(!config.enabled||!config.lockOnScreenLock){await chrome.alarms.clear(DEVICE_LOCK_ALARM);return;}
    let alarm=await chrome.alarms.get(DEVICE_LOCK_ALARM);
    if(!alarm){
        chrome.alarms.create(DEVICE_LOCK_ALARM,{periodInMinutes:DEVICE_LOCK_CHECK_MINUTES});
        alarm=await chrome.alarms.get(DEVICE_LOCK_ALARM);
    }
    await enforceDeviceSuspendLock(alarm);
}

async function networkRestored() {
    resetNetworkBackoff(); // Preserve explicit server Retry-After; discard transient network backoff.
    await schedulePendingSync(0);
    void synchronize().catch(() => null);
    void pollConnectivity().catch(() => null);
    return true;
}
self.addEventListener("online", () => { void networkRestored().catch(() => null); });
self.addEventListener("offline", () => schedulePendingSync(10000));
chrome.idle.onStateChanged.addListener((state)=>{if(state==="locked")enforceDeviceScreenLock(state).catch(()=>null);});
chrome.runtime.onStartup.addListener(() => { schedulePendingSync(0);synchronize().catch(() => null);pollConnectivity().catch(()=>null);ensureDeviceLockWatch().catch(()=>null); });
chrome.runtime.onInstalled.addListener(() => { chrome.alarms.create("lockstep-sync", { periodInMinutes: BACKGROUND_SYNC_MINUTES });schedulePendingSync(0);scheduleConnectivityCheck();ensureDeviceLockWatch().catch(()=>null); });
chrome.alarms.onAlarm.addListener((alarm) => {
    if(alarm.name === "lockstep-lock")subject().then(enforceTimedLock).catch(()=>null);
    if(alarm.name === PENDING_SYNC_ALARM)retryPendingSync().catch(()=>null);
    if (alarm.name === "lockstep-sync") { retryPendingSync().catch(() => null);enforceDeviceScreenLock().catch(()=>null); }
    if (alarm.name === CONNECTIVITY_ALARM) pollConnectivity().catch(()=>null);
    if (alarm.name === DEVICE_LOCK_ALARM) enforceDeviceSuspendLock(alarm).catch(()=>null);
});
chrome.alarms.create("lockstep-sync", { periodInMinutes: BACKGROUND_SYNC_MINUTES });
scheduleConnectivityCheck();
ensureDeviceLockWatch().catch(()=>null);
