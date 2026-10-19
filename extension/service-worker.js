importScripts("config.js", "crypto-store.js");

let lastSyncError = null;
let tokenRefreshPromise = null;

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
        SET_LOCK_CONFIG: () => message.initialSetup ? setLockConfig(message.passcode, message.timeoutSeconds, true) : withUnlocked(() => setLockConfig(message.passcode, message.timeoutSeconds, false)),
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
        SYNC_NOW: synchronize
    };
    if (!Object.hasOwn(actions, message.type)) return false;
    Promise.resolve().then(() => actions[message.type]())
        .then(data => sendResponse({ ok: true, data }))
        .catch(error => sendResponse({ ok: false, error: error?.message || "The requested extension action failed.", code: error?.code }));
    return true;
});

async function login() {
    const claims = await authorize(true);
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
    await synchronize().catch(() => null);
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
    await chrome.storage.session.clear();
    await chrome.storage.local.remove(["vaultSubject", "vaultDisplayName", "cachedLockConfig"]);
}

async function subject() {
    const session = await chrome.storage.session.get("idToken");
    if (session.idToken) return parseClaims(session.idToken).sub;
    const local = await chrome.storage.local.get(["vaultSubject", "vaultDisplayName"]);
    if (!local.vaultSubject) throw new Error("Sign in to Lockstep first.");
    return local.vaultSubject;
}

function coded(code, message) { const error = new Error(message); error.code = code; return error; }

async function withUnlocked(action) {
    const owner = await subject();
    if (!LockstepVault.isUnlocked(owner)) throw coded("VAULT_LOCKED", "Unlock the authenticator before using this feature.");
    return action();
}

async function token() {
    const session = await chrome.storage.session.get(["idToken", "tokenExpiry"]);
    if (session.idToken && session.tokenExpiry >= Date.now() + 30000) return session.idToken;
    try {
        tokenRefreshPromise ||= authorize(false).finally(() => { tokenRefreshPromise = null; });
        await tokenRefreshPromise;
        const refreshed = await chrome.storage.session.get(["idToken", "tokenExpiry"]);
        if (refreshed.idToken && refreshed.tokenExpiry >= Date.now() + 30000) return refreshed.idToken;
    } catch {}
    throw coded("SESSION_EXPIRED", "Sign in again to synchronize.");
}

async function tokenValid() { try { await token(); return true; } catch { return false; } }

async function backendAccountExists() {
    return (await api("/api/v1/account")).exists;
}

// Single source of truth for popup routing: who is signed in, is the Google token usable,
// and does this device actually hold the vault master key.
async function vaultState() {
    const local = await chrome.storage.local.get(["vaultSubject", "vaultDisplayName"]);
    const session = await chrome.storage.session.get("idToken");
    const sessionClaims = session.idToken ? parseClaims(session.idToken) : null;
    const owner = sessionClaims?.sub || local.vaultSubject;
    if (!owner) return { hasSubject: false };
    const validToken = await tokenValid();
    const refreshedSession = validToken ? await chrome.storage.session.get("idToken") : session;
    const refreshedClaims = refreshedSession.idToken ? parseClaims(refreshedSession.idToken) : sessionClaims;
    const refreshedLocal = await chrome.storage.local.get("vaultDisplayName");
    const sessionFlags = await chrome.storage.session.get(["newAccountSetupAuthorized", "restoreAuthorized"]);
    let accountExists = null;
    if (validToken) {
        accountExists = await backendAccountExists();
        if (accountExists) {
            const config = await api("/api/v1/lock");
            await LockstepVault.synchronizeWrappedKey(owner, config.wrappedKey);
            await chrome.storage.local.set({ cachedLockConfig: config });
        }
    }
    if (accountExists === false && !sessionFlags.newAccountSetupAuthorized) {
        await LockstepVault.clearSubject(owner);
        await chrome.storage.local.remove("cachedLockConfig");
        await chrome.storage.session.remove("lastUnlockedAt");
        lastSyncError = null;
    }
    return {
        hasSubject: true,
        displayName: refreshedClaims?.name || refreshedClaims?.given_name || refreshedClaims?.email || refreshedLocal.vaultDisplayName || local.vaultDisplayName || "",
        tokenValid: validToken,
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

async function synchronize() {
    const owner = await subject();
    try {
        if (!await backendAccountExists()) throw coded("ACCOUNT_MISSING", "Your server account no longer exists. Sign in again to start fresh.");
        const result = await LockstepVault.synchronize(owner, transport());
        lastSyncError = null;
        return result;
    } catch (error) {
        lastSyncError = error?.message || "Synchronization failed.";
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
    if (await tokenValid()) {
        const config = await api("/api/v1/lock");
        const changed = await LockstepVault.synchronizeWrappedKey(owner, config.wrappedKey);
        await chrome.storage.local.set({ cachedLockConfig: config });
        if (changed) throw coded("VAULT_LOCKED", "The synchronized passkey changed. Unlock the vault again before downloading its recovery key.");
    }
    return LockstepVault.exportRecoveryKey(owner);
}
async function importRecoveryKey(value, passcode) {
    await token(); // fail early (SESSION_EXPIRED) before touching local state
    const owner = await subject();
    await synchronize(); // restoration must fail closed unless ciphertext is available for key verification
    const version = await LockstepVault.importRecoveryKey(owner, value, passcode);
    const cached = (await chrome.storage.local.get("cachedLockConfig")).cachedLockConfig;
    const wrappedKey = await LockstepVault.exportWrappedKey(owner);
    const config = await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ passcode, timeoutSeconds: cached?.timeoutSeconds || 0, wrappedKey }) });
    await chrome.storage.local.set({ cachedLockConfig: config });
    await chrome.storage.session.remove("restoreAuthorized");
    return { version, entries: await localEntries() };
}
async function rotateEncryptionKey(passcode) {
    await token(); // rotation needs a live session: the new wrapped key must reach the server
    const owner = await subject();
    await synchronize(); // fully synced before the key changes
    const remaining = await LockstepVault.pendingCount(owner);
    if (remaining > 0) throw new Error(`Cannot rotate while ${remaining} change${remaining === 1 ? " is" : "s are"} pending synchronization.`);
    const result = await LockstepVault.rotateMasterKey(owner, passcode); // new master key, atomic local commit
    try {
        // Publish the new wrapped key BEFORE the re-encrypted entries so other devices can always decrypt what they pull.
        const cached = (await chrome.storage.local.get("cachedLockConfig")).cachedLockConfig;
        const config = await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ passcode, timeoutSeconds: cached?.timeoutSeconds || 0, wrappedKey: result.wrappedKey }) });
        await chrome.storage.local.set({ cachedLockConfig: config });
        await synchronize();
        return { version: result.version, count: result.count, recoveryKey: result.recoveryKey, rotated: true, synchronized: true };
    } catch (error) {
        return { version: result.version, count: result.count, recoveryKey: result.recoveryKey, rotated: true, synchronized: false, syncError: error?.message || "Synchronization failed." };
    }
}
async function syncState() {
    return { online: navigator.onLine, pending: await LockstepVault.pendingCount(await subject()), error: lastSyncError };
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
        if (!config && keyState === "wrapped") config = { enabled: true, timeoutSeconds: 0 };
        if (!config) throw coded("SESSION_EXPIRED", "Sign in again to synchronize.");
    }
    // A passkey-wrapped key on this device means the lock is on, whatever a stale cache/server says.
    if (keyState === "wrapped" && !config.enabled) config = { ...config, enabled: true };
    return config;
}
async function setLockConfig(passcode, timeoutSeconds, initialSetup = false) {
    const vaultSubject = await subject();
    await token(); // SESSION_EXPIRED up front, before any local key material changes
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
    config = await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ passcode, timeoutSeconds, wrappedKey }) });
    await chrome.storage.local.set({ cachedLockConfig: config });
    await chrome.storage.session.remove("newAccountSetupAuthorized");
    return config;
}
async function verifyLock(passcode) {
    const owner = await subject();
    const online = await tokenValid();
    if (online) {
        const latest = await api("/api/v1/lock");
        await LockstepVault.synchronizeWrappedKey(owner, latest.wrappedKey);
        await chrome.storage.local.set({ cachedLockConfig: latest });
    }
    const keyState = await LockstepVault.keyState(owner);
    if (keyState === "none") {
        // No key on this device (reset / cleared storage). A correct passkey cannot help; need recovery key.
        if (!online) throw coded("SESSION_EXPIRED", "Sign in again to restore your vault.");
        throw coded("KEY_MISSING", "This device does not have your vault key. Restore it with your recovery key.");
    }
    try {
        // Local AES-GCM unwrap is authoritative and works offline / with an expired Google token.
        await LockstepVault.unlock(owner, passcode);
        if (online) {
            // Firestore may have been manually cleared while this device retained its
            // wrapped master key. Recreate the missing verifier from the passkey that
            // just successfully unwrapped the local vault before entries synchronize.
            const serverConfig = await api("/api/v1/lock");
            const localWrapped = await LockstepVault.exportWrappedKey(owner);
            const localNewer = Number(localWrapped?.wrappedAt || localWrapped?.createdAt || 0) > Number(serverConfig.wrappedKey?.wrappedAt || serverConfig.wrappedKey?.createdAt || 0);
            // Also republish when this device holds a newer wrapped key (e.g. a rotation whose upload failed).
            if (!serverConfig.enabled || localNewer) {
                const cached = await chrome.storage.local.get("cachedLockConfig");
                const timeoutSeconds = cached.cachedLockConfig?.timeoutSeconds || 0;
                const restored = await api("/api/v1/lock", {
                    method: "PUT",
                    body: JSON.stringify({ passcode, timeoutSeconds, wrappedKey: await LockstepVault.exportWrappedKey(owner) })
                });
                await chrome.storage.local.set({ cachedLockConfig: restored });
            }
        }
        return { unlocked: true };
    } catch (error) {
        if (error.code !== "WRONG_PASSKEY" || !online) throw error;
        // Local passkey wrong. If the server accepts it, the passkey was changed on another device.
        const server = await api("/api/v1/lock/verify", { method: "POST", body: JSON.stringify({ passcode }) }).catch(() => null);
        if (server?.unlocked) throw coded("NEEDS_RECOVERY", "Your passkey was changed on another device. Enter your recovery key to update this one.");
        throw error;
    }
}
async function lockVault() { LockstepVault.lock(await subject()); }
async function resetVault() {
    const owner = await subject();
    await token();
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
    const response = await fetch(AUTHSYNC_CONFIG.apiBaseUrl + path, {
        ...options, cache: "no-store",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${await token()}` }
    });
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || (response.status === 401 ? "Sign in again." : `Request failed (${response.status})`));
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

self.addEventListener("online", () => synchronize().catch(() => null));
chrome.runtime.onStartup.addListener(() => synchronize().catch(() => null));
chrome.runtime.onInstalled.addListener(() => chrome.alarms.create("lockstep-sync", { periodInMinutes: 0.5 }));
chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "lockstep-sync") synchronize().catch(() => null);
});
chrome.alarms.create("lockstep-sync", { periodInMinutes: 0.5 });
