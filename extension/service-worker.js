importScripts("config.js", "crypto-store.js");

let lastSyncError = null;
let tokenRefreshPromise = null;
let activeScannerTabId = null;
const PENDING_SYNC_ALARM = "lockstep-pending-sync";
const CONNECTIVITY_ALARM = "lockstep-connectivity-check";
const DEVICE_LOCK_ALARM = "lockstep-device-lock-check";
const DEVICE_LOCK_CHECK_MINUTES = 0.5;
const DEVICE_SUSPEND_GRACE_MS = 10000;
const SESSION_REVOKED_NOTICE_KEY = "sessionRevokedNotice";
let pendingSyncPromise = null;
let pendingSyncTimeout = null;
let connectivityPollPromise = null;
let connectivityTimeout = null;
const ALLOWED_LOCK_TIMEOUTS = new Set([300,600,900,1200,1500,1800,2100,2400,2700,3000,3300,3600,7200,14400,28800,43200,86400,172800,604800]);

function schedulePendingSync(delay = 0) {
    clearTimeout(pendingSyncTimeout);
    pendingSyncTimeout=null;
    pendingSyncTimeout=setTimeout(()=>retryPendingSync().catch(()=>null),delay);
    return chrome.alarms.create(PENDING_SYNC_ALARM,{when:Date.now()+Math.max(1,delay)});
}

async function stopPendingSync() {
    clearTimeout(pendingSyncTimeout);pendingSyncTimeout=null;
    await chrome.alarms.clear(PENDING_SYNC_ALARM);
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
        if(!navigator.onLine){await schedulePendingSync(10000);return;}
        try{await LockstepVault.flushOutbox(owner,transport());lastSyncError=null;}
        catch(error){lastSyncError=error?.message||"Synchronization failed.";}
        if(!(await chrome.storage.local.get("vaultSubject")).vaultSubject){await stopPendingSync();return;}
        pending=await LockstepVault.pendingCount(owner);
        if(pending)await schedulePendingSync(10000);
        else await stopPendingSync();
    })().finally(()=>{pendingSyncPromise=null;});
    return pendingSyncPromise;
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    const actions = {
        LOGIN: login,
        LOGOUT: logout,
        LIST_ENTRIES: () => withUnlocked(listEntries),
        GET_CACHED_ENTRIES: () => withUnlocked(localEntries),
        START_SCAN: () => withUnlocked(startScan),
        ADD_OTP_URI: () => withUnlocked(() => addOtpUri(message.otpAuthUri)),
        IMPORT_ENTRIES: () => withUnlocked(() => importEntries(message.otpAuthUris)),
        EXPORT_ENTRIES: () => withUnlocked(exportEntries),
        GET_ENTRY_QR: () => withUnlocked(() => localOtpUri(message.id)),
        GET_VAULT_STATE: vaultState,
        GET_LOCK_CONFIG: getLockConfig,
        RESUME_VAULT: resumeVault,
        TOUCH_VAULT: touchVault,
        SET_LOCK_CONFIG: () => message.initialSetup ? setLockConfig(message.passcode, message.timeoutSeconds, message.lockOnScreenLock, true) : withUnlocked(() => setLockConfig(message.passcode, message.timeoutSeconds, message.lockOnScreenLock, false)),
        VERIFY_LOCK: () => verifyLock(message.passcode),
        LOCK_VAULT: lockVault,
        REMOVE_LOCK: removeLock,
        UPDATE_ENTRY: () => withUnlocked(() => updateEntry(message.id, message.issuer, message.accountName)),
        DELETE_ENTRY: () => withUnlocked(() => deleteEntry(message.id)),
        EXPORT_RECOVERY_KEY: () => withUnlocked(exportRecoveryKey),
        IMPORT_RECOVERY_KEY: () => message.recoveryMode ? importRecoveryKey(message.recoveryKey, message.passcode) : withUnlocked(() => importRecoveryKey(message.recoveryKey, message.passcode)),
        RESET_VAULT: resetVault,
        ROTATE_ENCRYPTION_KEY: () => withUnlocked(() => rotateEncryptionKey(message.passcode)),
        GET_SYNC_STATE: syncState,
        CHECK_CONNECTIVITY: checkConnectivity,
        CHECK_SESSION: checkActiveSession,
        SYNC_NOW: synchronize,
        OPEN_PRIVACY: openPrivacyPolicy
    };
    if (!Object.hasOwn(actions, message.type)) return false;
    Promise.resolve().then(() => actions[message.type]())
        .then(data => sendResponse({ ok: true, data }))
        .catch(error => sendResponse({ ok: false, error: error?.message || "The requested extension action failed.", code: error?.code }));
    return true;
});

async function openPrivacyPolicy() {
    const baseUrl = String(AUTHSYNC_CONFIG.webBaseUrl || "").replace(/\/+$/, "");
    if (!baseUrl) throw new Error("The Lockstep web app URL is not configured.");
    await chrome.tabs.create({ url: `${baseUrl}/privacy.html` });
    return true;
}

async function login() {
    const claims = await authorize(true);
    await chrome.storage.local.remove(SESSION_REVOKED_NOTICE_KEY);
    await registerAppSession();
    const exists = await backendAccountExists();
    if (!exists) {
        await LockstepVault.clearSubject(claims.sub);
        await chrome.storage.local.remove("cachedLockConfig");
        await chrome.storage.session.set({ newAccountSetupAuthorized: true });
        lastSyncError = null;
        return { email: claims.email, displayName: claims.name || claims.given_name || claims.email, newAccount: true };
    }
    await chrome.storage.session.remove("newAccountSetupAuthorized");
    if (await LockstepVault.keyState(claims.sub) === "none") await chrome.storage.session.set({ restoreAuthorized: true });
    else await chrome.storage.session.remove("restoreAuthorized");
    await synchronize(await LockstepVault.keyState(claims.sub)==="none").catch(() => null);
    return { email: claims.email, displayName: claims.name || claims.given_name || claims.email, newAccount: false };
}

async function authorize(interactive) {
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
    if (!idToken) throw new Error("Google did not return an ID token.");
    const claims = parseClaims(idToken);
    if (claims.nonce !== nonce) throw new Error("Google sign-in nonce did not match.");
    const local = await chrome.storage.local.get("vaultSubject");
    if (!interactive && local.vaultSubject && local.vaultSubject !== claims.sub) {
        throw coded("SESSION_EXPIRED", "Sign in again to synchronize.");
    }
    await chrome.storage.session.set({ idToken, tokenExpiry: claims.exp * 1000 });
    await chrome.storage.local.set({ vaultSubject: claims.sub, vaultDisplayName: claims.name || claims.given_name || claims.email || "" });
    return claims;
}

async function logout() {
    try { LockstepVault.lock(await subject()); } catch {}
    await stopPendingSync();
    await chrome.storage.session.clear();
    await chrome.storage.local.remove(["vaultSubject", "vaultDisplayName", "cachedLockConfig", "appSessionId", "appSessionExpiry", "idToken", "tokenExpiry"]);
}

async function invalidateAuthentication(message = "") {
    try { LockstepVault.lock(await subject()); } catch {}
    await stopPendingSync();
    await chrome.storage.session.clear();
    await chrome.storage.local.remove(["vaultSubject", "vaultDisplayName", "cachedLockConfig", "appSessionId", "appSessionExpiry", "idToken", "tokenExpiry"]);
    if(message)await chrome.storage.local.set({[SESSION_REVOKED_NOTICE_KEY]:message});
}

async function subject() {
    const tokenState=await storedGoogleToken();
    if(tokenState.idToken)return parseClaims(tokenState.idToken).sub;
    const local = await chrome.storage.local.get(["vaultSubject", "vaultDisplayName"]);
    if (!local.vaultSubject) throw new Error("Sign in to Lockstep first.");
    return local.vaultSubject;
}

function coded(code, message) { const error = new Error(message); error.code = code; return error; }

async function withUnlocked(action) {
    const owner = await subject();
    await enforceDeviceSuspendLock(await chrome.alarms.get(DEVICE_LOCK_ALARM));
    await enforceTimedLock(owner);
    if (!LockstepVault.isUnlocked(owner)) throw coded("VAULT_LOCKED", "Unlock the authenticator before using this feature.");
    const result=await action();
    if(!LockstepVault.isUnlocked(owner))throw coded("VAULT_LOCKED","Vault locked while the operation was finishing. Your accepted change was saved safely.");
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
    const snapshot = LockstepVault.exportSessionKey(owner);
    await chrome.storage.session.set({ lastUnlockedAt, unlockedMaster: snapshot ? { subject: owner, snapshot } : null });
    chrome.alarms.create("lockstep-lock",{when:lastUnlockedAt+lock.timeoutSeconds*1000});
}

async function clearUnlockedSession(owner) {
    LockstepVault.lock(owner);
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
    if (!session.lastUnlockedAt || Date.now() - session.lastUnlockedAt >= config.timeoutSeconds * 1000) await clearUnlockedSession(owner);
}

async function resumeVault() {
    const owner = await subject();
    const config = await getLockConfig();
    if (!config.enabled) { await clearUnlockedSession(owner); return false; }
    const session = await chrome.storage.session.get(["lastUnlockedAt", "unlockedMaster"]);
    if (!session.lastUnlockedAt || Date.now() - session.lastUnlockedAt >= config.timeoutSeconds * 1000) { await clearUnlockedSession(owner); return false; }
    if (!LockstepVault.isUnlocked(owner)) {
        if (session.unlockedMaster?.subject !== owner || !await LockstepVault.restoreSessionKey(owner, session.unlockedMaster.snapshot)) {
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
    const stored=await storedGoogleToken();
    if(stored.idToken&&stored.tokenExpiry>=Date.now()+30000)return stored.idToken;
    try {
        tokenRefreshPromise ||= authorize(false).finally(() => { tokenRefreshPromise = null; });
        await tokenRefreshPromise;
        const refreshed = await storedGoogleToken();
        if (refreshed.idToken && refreshed.tokenExpiry >= Date.now() + 30000) return refreshed.idToken;
    } catch {}
    await chrome.storage.session.remove(["idToken","tokenExpiry"]);
    throw coded("SESSION_EXPIRED", "Sign in again to synchronize.");
}

async function storedGoogleToken(){
    return chrome.storage.session.get(["idToken","tokenExpiry"]);
}

async function backendAccountExists() {
    return (await api("/api/v1/account")).exists;
}

// Single source of truth for popup routing: who is signed in, is the Google token usable,
// and does this device actually hold the vault master key.
async function vaultState() {
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
            accountExists = await backendAccountExists();
            if (accountExists) {
                const config = await api("/api/v1/lock");
                await LockstepVault.synchronizeWrappedKey(owner, config.wrappedKey);
                await chrome.storage.local.set({ cachedLockConfig: config });
            }
        } catch { accountExists = null; }
    }
    if (accountExists === false && !sessionFlags.newAccountSetupAuthorized) {
        await LockstepVault.clearSubject(owner);
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

function transport() {
    return {
        list: () => api("/api/v1/entries"),
        put: (id, payload) => api(`/api/v1/entries/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
        delete: (id) => api(`/api/v1/entries/${id}`, { method: "DELETE" })
    };
}

async function synchronize(allowLockedPull = false) {
    const owner = await subject();
    try {
        if(!LockstepVault.isUnlocked(owner)&&!allowLockedPull){
            const result=await LockstepVault.flushOutbox(owner,transport());
            lastSyncError=null;
            if(result.pending)await schedulePendingSync(10000);else await stopPendingSync();
            return result;
        }
        if (!await backendAccountExists()) throw coded("ACCOUNT_MISSING", "Your server account no longer exists. Sign in again to start fresh.");
        const result = await LockstepVault.synchronize(owner, transport(),allowLockedPull);
        lastSyncError = null;
        if(result.pending)await schedulePendingSync(10000);else await stopPendingSync();
        return result;
    } catch (error) {
        lastSyncError = error?.message || "Synchronization failed.";
        if(await LockstepVault.pendingCount(owner))await schedulePendingSync(10000);
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

async function deleteEntry(id) {
    await LockstepVault.deleteEntry(await subject(), id);
    await synchronize().catch(() => null);
    return null;
}

async function importEntries(otpAuthUris) {
    if (!Array.isArray(otpAuthUris) || otpAuthUris.length === 0 || otpAuthUris.length > 500) {
        throw new Error("Choose a valid Lockstep backup containing 1 to 500 entries.");
    }
    let imported = 0, failed = 0;
    for (const uri of otpAuthUris) {
        try { await LockstepVault.addOtpUri(await subject(), uri); imported++; } catch { failed++; }
    }
    await synchronize().catch(() => null);
    return { imported, failed };
}

async function exportEntries() { return LockstepVault.exportText(await subject()); }
async function localOtpUri(id) { return LockstepVault.otpAuthUri(await subject(), id); }
async function exportRecoveryKey() {
    const owner = await subject();
    if (navigator.onLine&&await activeAppSession().then(()=>true).catch(()=>false)) {
        const config = await api("/api/v1/lock");
        const changed = await LockstepVault.synchronizeWrappedKey(owner, config.wrappedKey);
        await chrome.storage.local.set({ cachedLockConfig: config });
        if (changed) throw coded("VAULT_LOCKED", "The synchronized passkey changed. Unlock the vault again before downloading its recovery key.");
    }
    return LockstepVault.exportRecoveryKey(owner);
}
async function importRecoveryKey(value, passcode) {
    await activeAppSession(); // fail before touching local state if the 30-day session ended
    const owner = await subject();
    await synchronize(true); // restoration is the explicit locked flow allowed to download ciphertext for key verification
    const version = await LockstepVault.importRecoveryKey(owner, value, passcode);
    const cached = (await chrome.storage.local.get("cachedLockConfig")).cachedLockConfig;
    const wrappedKey = await LockstepVault.exportWrappedKey(owner);
    const config = await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ passcode, timeoutSeconds: cached?.timeoutSeconds || 300, lockOnScreenLock:Boolean(cached?.lockOnScreenLock), wrappedKey }) });
    await chrome.storage.local.set({ cachedLockConfig: config });
    await chrome.storage.session.remove("restoreAuthorized");
    await persistUnlockedSession(owner, config);
    return { version, entries: await localEntries() };
}
async function rotateEncryptionKey(passcode) {
    await activeAppSession(); // rotation needs a live session: the new wrapped key must reach the server
    const owner = await subject();
    await synchronize(); // fully synced before the key changes
    const remaining = await LockstepVault.pendingCount(owner);
    if (remaining > 0) throw new Error(`Cannot rotate while ${remaining} change${remaining === 1 ? " is" : "s are"} pending synchronization.`);
    const result = await LockstepVault.rotateMasterKey(owner, passcode); // new master key, atomic local commit
    try {
        // Publish the new wrapped key BEFORE the re-encrypted entries so other devices can always decrypt what they pull.
        const cached = (await chrome.storage.local.get("cachedLockConfig")).cachedLockConfig;
        const config = await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ passcode, timeoutSeconds: cached?.timeoutSeconds || 300, lockOnScreenLock:Boolean(cached?.lockOnScreenLock), wrappedKey: result.wrappedKey }) });
        await chrome.storage.local.set({ cachedLockConfig: config });
        await synchronize();
        await persistUnlockedSession(owner, config);
        return { version: result.version, count: result.count, recoveryKey: result.recoveryKey, rotated: true, synchronized: true };
    } catch (error) {
        return { version: result.version, count: result.count, recoveryKey: result.recoveryKey, rotated: true, synchronized: false, syncError: error?.message || "Synchronization failed." };
    }
}
async function syncState() {
    return { online: await checkConnectivity(), pending: await LockstepVault.pendingCount(await subject()), error: lastSyncError };
}

async function registerAppSession() {
    const response=await fetch(AUTHSYNC_CONFIG.apiBaseUrl+"/api/v1/session",{
        method:"POST",cache:"no-store",
        headers:{"Content-Type":"application/json",Authorization:`Bearer ${await token()}`,"X-Lockstep-Client":"extension"}
    });
    const body=await response.json().catch(()=>({}));
    if(!response.ok||!body.sessionToken){
        throw coded(body.code||(response.status===401?"SESSION_EXPIRED":"REQUEST_FAILED"),body.error||(response.status===401?"Sign in again.":`Request failed (${response.status})`));
    }
    await chrome.storage.local.set({appSessionId:body.sessionToken,appSessionExpiry:Number(body.expiresAtEpochMillis)||0});
    return body.sessionToken;
}

async function appSession() {
    const stored=await chrome.storage.local.get(["appSessionId","appSessionExpiry"]);
    if(stored.appSessionId&&Number(stored.appSessionExpiry)>Date.now())return stored.appSessionId;
    if(stored.appSessionId){
        const error=coded("SESSION_EXPIRED","Your 30-day Lockstep session has expired. Sign in with Google again.");
        await invalidateAuthentication(error.message);
        throw error;
    }
    throw coded("SESSION_EXPIRED","Sign in with Google to start a new 30-day Lockstep session.");
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
    connectivityTimeout=setTimeout(()=>pollConnectivity().catch(()=>null),10000);
    chrome.alarms.create(CONNECTIVITY_ALARM,{when:Date.now()+10000});
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
        config = await api("/api/v1/lock");
        await LockstepVault.synchronizeWrappedKey(owner, config.wrappedKey);
        await chrome.storage.local.set({ cachedLockConfig: config });
    } catch {
        const cached = await chrome.storage.local.get("cachedLockConfig");
        config = cached.cachedLockConfig;
        // Offline / expired token but this device holds a protected key: the lock obviously exists.
        if (!config && keyState === "wrapped") config = { enabled: true, timeoutSeconds: 300, lockOnScreenLock:false };
        if (!config) throw coded("SESSION_EXPIRED", "Sign in again to synchronize.");
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
    let config;
    if (initialSetup) {
        // Never mint a new master key if the server already holds ciphertext we cannot decrypt
        // (reset laptop / cleared IndexedDB): that would orphan the whole vault.
        await synchronize().catch(() => null);
        if (await LockstepVault.keyState(vaultSubject) === "none" && (await LockstepVault.localEncryptedEntries(vaultSubject)).length > 0) {
            throw coded("KEY_MISSING", "Your accounts are stored but this device has no vault key. Restore it with your recovery key.");
        }
        await LockstepVault.configurePassphrase(vaultSubject, passcode);
    } else {
        await LockstepVault.configurePassphrase(vaultSubject, passcode);
    }
    const wrappedKey = await LockstepVault.exportWrappedKey(vaultSubject);
    config = await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ passcode, timeoutSeconds, lockOnScreenLock:Boolean(lockOnScreenLock), wrappedKey }) });
    await chrome.storage.local.set({ cachedLockConfig: config });
    await chrome.storage.session.remove("newAccountSetupAuthorized");
    await persistUnlockedSession(vaultSubject, config);
    return config;
}
async function verifyLock(passcode) {
    const owner = await subject();
    let serverAvailable = false;
    if (navigator.onLine&&await activeAppSession().then(()=>true).catch(()=>false)) {
        try {
            const latest = await api("/api/v1/lock");
            await LockstepVault.synchronizeWrappedKey(owner, latest.wrappedKey);
            await chrome.storage.local.set({ cachedLockConfig: latest });
            serverAvailable = true;
        } catch { /* The local passkey remains authoritative while offline. */ }
    }
    const keyState = await LockstepVault.keyState(owner);
    if (keyState === "none") {
        // No key on this device (reset / cleared storage). A correct passkey cannot help; need recovery key.
        if (!serverAvailable) throw coded("SESSION_EXPIRED", "Sign in again to restore your vault.");
        throw coded("KEY_MISSING", "This device does not have your vault key. Restore it with your recovery key.");
    }
    try {
        // Local AES-GCM unwrap is authoritative and works offline / with an expired Google token.
        await LockstepVault.unlock(owner, passcode);
        if (serverAvailable) {
            // Firestore may have been manually cleared while this device retained its
            // wrapped master key. Recreate the missing verifier from the passkey that
            // just successfully unwrapped the local vault before entries synchronize.
            const serverConfig = await api("/api/v1/lock");
            const localWrapped = await LockstepVault.exportWrappedKey(owner);
            const localNewer = Number(localWrapped?.wrappedAt || localWrapped?.createdAt || 0) > Number(serverConfig.wrappedKey?.wrappedAt || serverConfig.wrappedKey?.createdAt || 0);
            // Also republish when this device holds a newer wrapped key (e.g. a rotation whose upload failed).
            if (!serverConfig.enabled || localNewer) {
                const cached = await chrome.storage.local.get("cachedLockConfig");
                const timeoutSeconds = cached.cachedLockConfig?.timeoutSeconds || 300;
                const restored = await api("/api/v1/lock", {
                    method: "PUT",
                    body: JSON.stringify({ passcode, timeoutSeconds, lockOnScreenLock:Boolean(cached.cachedLockConfig?.lockOnScreenLock), wrappedKey: await LockstepVault.exportWrappedKey(owner) })
                });
                await chrome.storage.local.set({ cachedLockConfig: restored });
            }
        }
        await persistUnlockedSession(owner, await cachedLockConfig());
        return { unlocked: true };
    } catch (error) {
        if (error.code !== "WRONG_PASSKEY" || !serverAvailable) throw error;
        // Local passkey wrong. If the server accepts it, the passkey was changed on another device.
        const server = await api("/api/v1/lock/verify", { method: "POST", body: JSON.stringify({ passcode }) }).catch(() => null);
        if (server?.unlocked) throw coded("NEEDS_RECOVERY", "Your passkey was changed on another device. Enter your recovery key to update this one.");
        throw error;
    }
}
async function lockVault() {
    const owner=await subject();
    await clearUnlockedSession(owner);
}
async function resetVault() {
    const owner = await subject();
    await activeAppSession();
    await api("/api/v1/vault", { method: "DELETE" });
    await LockstepVault.clearSubject(owner);
    await chrome.storage.local.remove("cachedLockConfig");
    await chrome.storage.session.remove("lastUnlockedAt");
    await chrome.storage.session.remove("restoreAuthorized");
    return true;
}
async function removeLock() {
    throw new Error("The vault passkey cannot be removed because it encrypts the local master key. You can change it instead.");
}

async function api(path, options = {}) {
    const sessionToken=await appSession();
    const googleToken=await token().catch(()=>"");
    const owner=await subject();
    const headers={ "Content-Type":"application/json", ...(googleToken?{Authorization:`Bearer ${googleToken}`}:{"X-Lockstep-Subject":owner}), "X-Lockstep-Client":"extension", "X-Lockstep-Session":sessionToken, ...options.headers };
    let response;
    try{
        response=await fetch(AUTHSYNC_CONFIG.apiBaseUrl+path,{...options,cache:"no-store",headers});
    }catch{
        throw coded("BACKEND_UNAVAILABLE","Backend is currently unavailable. Please try again when the service is back online.");
    }
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        const error=coded(body.code||(response.status===401?"SESSION_EXPIRED":"REQUEST_FAILED"),body.error||(response.status===401?"Sign in again.":`Request failed (${response.status})`));
        if(error.code==="SESSION_REVOKED"||error.code==="SESSION_EXPIRED")await invalidateAuthentication(error.message);
        throw error;
    }
    return response.status === 204 ? null : response.json();
}

async function startScan() {
    await subject();
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) throw new Error("No active tab found.");
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
        throw new Error("Chrome protects this page from extensions. Open the webpage containing the QR code, then scan again.");
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
    await clearUnlockedSession(owner);
    return true;
}

async function enforceDeviceSuspendLock(alarm = null) {
    const config=await cachedLockConfig();
    if(!config.enabled||!config.lockOnScreenLock)return false;
    const state=await chrome.idle.queryState(15);
    const resumedAfterSuspend=Boolean(alarm?.scheduledTime)&&Date.now()-alarm.scheduledTime>DEVICE_SUSPEND_GRACE_MS;
    if(state!=="locked"&&!resumedAfterSuspend)return false;
    let owner;try{owner=await subject();}catch{return false;}
    await clearUnlockedSession(owner);
    return true;
}

async function ensureDeviceLockWatch() {
    chrome.idle.setDetectionInterval(15);
    let alarm=await chrome.alarms.get(DEVICE_LOCK_ALARM);
    if(!alarm){
        chrome.alarms.create(DEVICE_LOCK_ALARM,{periodInMinutes:DEVICE_LOCK_CHECK_MINUTES});
        alarm=await chrome.alarms.get(DEVICE_LOCK_ALARM);
    }
    await enforceDeviceSuspendLock(alarm);
}

self.addEventListener("online", () => { schedulePendingSync(0);synchronize().catch(() => null);pollConnectivity().catch(()=>null); });
self.addEventListener("offline", () => schedulePendingSync(10000));
chrome.idle.onStateChanged.addListener((state)=>{if(state==="locked")enforceDeviceScreenLock(state).catch(()=>null);});
chrome.runtime.onStartup.addListener(() => { schedulePendingSync(0);synchronize().catch(() => null);pollConnectivity().catch(()=>null);ensureDeviceLockWatch().catch(()=>null); });
chrome.runtime.onInstalled.addListener(() => { chrome.alarms.create("lockstep-sync", { periodInMinutes: 0.5 });schedulePendingSync(0);scheduleConnectivityCheck();ensureDeviceLockWatch().catch(()=>null); });
chrome.alarms.onAlarm.addListener((alarm) => {
    if(alarm.name === "lockstep-lock")subject().then(enforceTimedLock).catch(()=>null);
    if(alarm.name === PENDING_SYNC_ALARM)retryPendingSync().catch(()=>null);
    if (alarm.name === "lockstep-sync") { synchronize().catch(() => null);enforceDeviceScreenLock().catch(()=>null); }
    if (alarm.name === CONNECTIVITY_ALARM) pollConnectivity().catch(()=>null);
    if (alarm.name === DEVICE_LOCK_ALARM) enforceDeviceSuspendLock(alarm).catch(()=>null);
});
chrome.alarms.create("lockstep-sync", { periodInMinutes: 0.5 });
scheduleConnectivityCheck();
ensureDeviceLockWatch().catch(()=>null);
