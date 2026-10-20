const el = (id) => document.getElementById(id);
const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"></use></svg>`;
const API_BASE_URL = String(globalThis.LOCKSTEP_CONFIG?.apiBaseUrl || location.origin).trim().replace(/\/+$/, "");
const apiUrl = (path) => `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;
const APP_BASE_URL = new URL(document.baseURI);
const EXPIRING_THRESHOLD_MILLIS = 5_000;
const DEVICE_LOCK_CHECK_MILLIS = 30_000;
const DEVICE_SUSPEND_GRACE_MILLIS = 10_000;
const SESSION_REVOKED_NOTICE_KEY = "authsync.sessionRevokedNotice";
const THEMES = ["light", "dark"];
const LOCK_TIMEOUT_LABELS = new Map([
    [300,"5 minutes"],[600,"10 minutes"],[900,"15 minutes"],[1200,"20 minutes"],[1500,"25 minutes"],
    [1800,"30 minutes"],[2100,"35 minutes"],[2400,"40 minutes"],[2700,"45 minutes"],[3000,"50 minutes"],
    [3300,"55 minutes"],[3600,"1 hour"],[7200,"2 hours"],[14400,"4 hours"],[28800,"8 hours"],
    [43200,"12 hours"],[86400,"1 day"],[172800,"2 days"],[604800,"1 week"]
]);
const state = {
    token: sessionStorage.getItem("authsync.idToken"), entries: [], serverOffsetMillis: 0,
    subject: localStorage.getItem("authsync.lastSubject"),
    refreshing: false, editing: false, originals: new Map(), pinnedIds: new Set(), entryOrder: [], dragId: null,
    theme: localStorage.getItem("authsync.theme") || "light", confirmationResolve: null, toastTimer: null, toastHideTimer: null, confirmPasskey: "",
    lockConfig: { enabled: false, timeoutSeconds: 300, lockOnScreenLock: false }, inactivityTimer: null, lastActivityAt: Date.now(), lastPointerActivityAt: 0, screenLockController: null,
    screenState: null, screenLockHeartbeatAt: Date.now(), screenLockHeartbeatVisible: !document.hidden,
    offline: false, pendingChanges: 0, lockSetupRequired: false, lastSyncError: null,
    restoreAuthorized: sessionStorage.getItem("authsync.restoreAuthorized") === "1", restoreReturnView: "signed-out",
    displayName: localStorage.getItem("authsync.displayName") || "",
    vaultEpoch: 0, vaultRequests: new AbortController(), tokenExpiryTimer: null,
    pendingSyncTimer: null, pendingSyncRunning: false, pendingSyncRequested: false
};
const cameraScanner = { stream:null, source:"camera", frameRequest:0, frameTimer:null, lastScanAt:0, frameCount:0, processing:false, lastValue:"", ignoreUntil:0, selection:null, selectionDrag:null };

function animateIn(element) {
    element.classList.remove("view-enter");
    void element.offsetWidth; // force reflow so animation re-fires
    element.classList.add("view-enter");
}

function hideLoader() {
    const loader = el("app-loading");
    const actions = el("app-actions");
    loader.style.transition = "opacity .18s ease";
    loader.style.opacity = "0";
    setTimeout(() => {
        loader.classList.add("hidden");
        loader.style.transition = "";
        loader.style.opacity = "";
        actions.style.transition = "opacity .22s ease";
        actions.style.opacity = "0";
        actions.style.visibility = "";
        requestAnimationFrame(() => { actions.style.opacity = "1"; });
        setTimeout(() => { actions.style.transition = ""; actions.style.opacity = ""; }, 250);
    }, 180);
}

function showLoader() {
    const loader = el("app-loading");
    loader.classList.remove("hidden");
    loader.style.transition = "";
    loader.style.opacity = "1";
}

async function initialize() {
    applyTheme(THEMES.includes(state.theme) ? state.theme : "light");
    renderConnectivityStatus(navigator.onLine);
    if(state.token&&!state.subject){state.token=null;sessionStorage.removeItem("authsync.idToken");}
    if(state.subject&&appSessionHasExpired())signOut(false,"Your 30-day Lockstep session has expired. Sign in with Google again.");
    if (state.token) {
        const claims = tokenClaims(state.token);
        state.displayName = claims?.name || claims?.given_name || claims?.email || state.displayName;
        if (state.displayName) localStorage.setItem("authsync.displayName", state.displayName);
        scheduleGoogleSessionExpiry();
    }
    if ("serviceWorker" in navigator) navigator.serviceWorker.register(new URL("sw.js", APP_BASE_URL));
    bindEvents();
    if (!isSecureGoogleOrigin()) {
        hideLoader();
        toast(`Google Sign-In requires HTTPS for ${location.hostname}. Current origin: ${location.origin}`, true); return;
    }
    let config = null;
    try {
        config = await fetch(apiUrl("/api/v1/config"), { cache: "no-store" }).then(response => response.json());
        if (config.googleClientId) localStorage.setItem("authsync.googleClientId", config.googleClientId);
    } catch { config = { googleClientId: localStorage.getItem("authsync.googleClientId") }; }
    if (config?.googleClientId && navigator.onLine) {
        try {
            await waitForGoogle();
            google.accounts.id.initialize({ client_id: config.googleClientId, callback: onGoogleCredential, auto_select: false });
            renderGoogleButton();
        } catch (error) { if (!state.token && !state.subject) throw error; }
    }
    if (state.token && navigator.onLine) await ensureAppSession().catch(() => null);
    if (state.token || state.subject) await showApp(false);
    else {
        signOut(false);
        if (!config?.googleClientId) toast("Backend is currently unavailable. Please try again when the service is back online.", true);
    }
    schedulePendingSync(0);
    checkConnectivity();
    void checkActiveSession();
    showStoredSessionRevokedNotice();
    hideLoader();
}

function bindEvents() {
    el("theme-toggle").addEventListener("click", cycleTheme);
    el("sign-out").addEventListener("click", () => signOut(true));
    el("open-settings").addEventListener("click", openSettings);
    el("settings-refresh").addEventListener("click", async () => {
        const button = el("settings-refresh");
        recordUserActivity();
        button.disabled = true;
        try {
            await loadEntries(true);
            if (!state.subject || !LockstepVault.isUnlocked(state.subject)) return;
            recordUserActivity();
            el("settings-dialog").close();
            toast("Accounts refreshed");
        } finally {
            button.disabled = false;
        }
    });
    el("settings-recovery-export").addEventListener("click", exportRecoveryKey);
    el("settings-key-rotate").addEventListener("click", rotateEncryptionKey);
    el("settings-signout").addEventListener("click", () => { el("settings-dialog").close(); signOut(true); });
    el("settings-lock").addEventListener("click", openLockSettings);
    el("lock-form").addEventListener("submit", saveLockSettings);
    el("lock-dialog").addEventListener("cancel", event => { if (state.lockSetupRequired) event.preventDefault(); });
    el("lock-now").addEventListener("click", () => { lockApp(); toast("Vault locked"); });
    el("unlock-form").addEventListener("submit", unlockApp);
    el("forgot-passkey").addEventListener("click", () => showRestore("locked"));
    el("restore-form").addEventListener("submit", restoreVault);
    el("restore-key-file").addEventListener("change", loadRecoveryKeyFile);
    el("restore-reset").addEventListener("click", resetVault);
    el("restore-signout").addEventListener("click", () => signOut(true));
    el("restore-back").addEventListener("click", () => state.restoreReturnView === "locked" ? showLocked() : signOut(false, "Local vault data was cleared. Sign in with Google again."));
    el("open-add").addEventListener("click", openAdd);
    el("edit-add").addEventListener("click", openAdd);
    el("empty-add").addEventListener("click", openAdd);
    el("close-add").addEventListener("click", closeAdd);
    el("open-camera").addEventListener("click", openCameraScanner);
    el("close-camera").addEventListener("click", () => el("camera-dialog").close());
    el("retry-camera").addEventListener("click", startCameraStream);
    el("clear-screen-selection").addEventListener("click", clearScreenSelection);
    el("camera-dialog").addEventListener("close", stopCameraScanner);
    el("camera-viewfinder").addEventListener("pointerdown",startScreenSelection);
    el("camera-viewfinder").addEventListener("pointermove",moveScreenSelection);
    el("camera-viewfinder").addEventListener("pointerup",finishScreenSelection);
    el("camera-viewfinder").addEventListener("pointercancel",finishScreenSelection);
    el("open-manual").addEventListener("click", () => openSubDialog("manual-dialog"));
    el("open-uris").addEventListener("click", () => openSubDialog("uri-dialog"));
    el("manual-form").addEventListener("submit", addManualEntry);
    el("uri-form").addEventListener("submit", importOtpUrls);
    el("qr-file").addEventListener("change", scanQrImage);
    document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => el(button.dataset.close).close()));
    el("edit-accounts").addEventListener("click", () => setEditing(true));
    el("save-edits").addEventListener("click", saveEdits);
    el("entries").addEventListener("click", handleEntryClick);
    el("entries").addEventListener("input", syncDraftsFromInputs);
    el("entries").addEventListener("dragstart", handleDragStart);
    el("entries").addEventListener("dragover", handleDragOver);
    el("entries").addEventListener("drop", handleDrop);
    el("entries").addEventListener("dragend", clearDragState);
    el("import-backup").addEventListener("click", () => el("backup-file").click());
    el("export-backup").addEventListener("click", exportBackup);
    el("backup-file").addEventListener("change", importBackup);
    el("close-qr").addEventListener("click", () => el("qr-dialog").close());
    el("qr-dialog").addEventListener("close", clearQrDialog);
    el("confirm-cancel").addEventListener("click", () => el("confirm-dialog").close("cancel"));
    el("confirm-accept").addEventListener("click", () => el("confirm-dialog").close("confirm"));
    el("confirm-dialog").addEventListener("close", resolveConfirmation);
    setInterval(tick, 100);
    setInterval(() => { if((state.token || state.subject) && !el("signed-in").classList.contains("hidden") && !document.hidden) loadEntries(); }, 30000);
    setInterval(()=>{checkConnectivity();void checkActiveSession();}, 10000);
    setInterval(enforceScreenLockHeartbeat,DEVICE_LOCK_CHECK_MILLIS);
    ["pointerdown","keydown","touchstart","scroll"].forEach((eventName)=>document.addEventListener(eventName,recordUserActivity,{passive:true}));
    document.addEventListener("pointermove",recordPointerActivity,{passive:true});
    document.addEventListener("visibilitychange",()=>{
        state.screenLockHeartbeatAt=Date.now();state.screenLockHeartbeatVisible=!document.hidden;
        if(document.hidden){stopInactivityWatch();if(el("camera-dialog").open&&cameraScanner.source!=="screen")el("camera-dialog").close();}
        else{enforceCurrentScreenLock();enforceInactivityLock();if((state.token||state.subject)&&!el("signed-in").classList.contains("hidden"))loadEntries();}
    });
    window.addEventListener("online", () => {
        checkConnectivity();
        void checkActiveSession();
        schedulePendingSync(0);
        if (isVaultOperational()) loadEntries(true);
    });
    window.addEventListener("offline",()=>{renderConnectivityStatus(false);stopPendingSyncRetry();});
    window.addEventListener("focus",enforceInactivityLock);window.addEventListener("pageshow",enforceInactivityLock);document.addEventListener("resume",enforceInactivityLock);
    setInterval(enforceInactivityLock,15000);
}

function isSecureGoogleOrigin() {
    return location.protocol === "https:" || ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
}

function renderConnectivityStatus(online) {
    const indicator=el("connectivity-status");
    if(!indicator)return;
    indicator.dataset.state=online?"online":"offline";
    indicator.querySelector(".connectivity-label").textContent=online?"Online":"Offline";
    indicator.title=online?"Device is connected to the internet":"Device is offline";
}

function checkConnectivity() {
    const online=navigator.onLine;
    renderConnectivityStatus(online);
    return online;
}

function showSessionRevoked(message="This Lockstep session was replaced by a login on another device.") {
    localStorage.setItem(SESSION_REVOKED_NOTICE_KEY,message);
    signOut(false,message);
    localStorage.removeItem(SESSION_REVOKED_NOTICE_KEY);
}

function showStoredSessionRevokedNotice() {
    const message=localStorage.getItem(SESSION_REVOKED_NOTICE_KEY);
    if(!message)return;
    localStorage.removeItem(SESSION_REVOKED_NOTICE_KEY);
    if(!state.token&&!state.subject)toast(message,true);
}

async function checkActiveSession() {
    if(!state.subject)return;
    if(appSessionHasExpired()){signOut(false,"Your 30-day Lockstep session has expired. Sign in with Google again.");return;}
    if(!navigator.onLine||!appSessionToken())return;
    const controller=new AbortController();
    const timeout=setTimeout(()=>controller.abort(),5000);
    try{
        await ensureAppSession();
        await authenticatedFetch("/api/v1/session",{signal:controller.signal});
    }catch(error){
        if(error.code==="SESSION_REVOKED"&&(state.token||state.subject))showSessionRevoked(error.message);
        else if(error.code==="SESSION_EXPIRED"&&(state.token||state.subject))signOut(false,error.message);
    }finally{clearTimeout(timeout);}
}

function waitForGoogle() {
    return new Promise((resolve, reject) => {
        const started = Date.now();
        const timer = setInterval(() => {
            if (window.google?.accounts?.id) { clearInterval(timer); resolve(); }
            else if (Date.now() - started > 10000) { clearInterval(timer); reject(new Error("Google Sign-In could not be loaded")); }
        }, 50);
    });
}

async function onGoogleCredential({ credential }) {
    showLoader();
    localStorage.removeItem(SESSION_REVOKED_NOTICE_KEY);
    const claims = tokenClaims(credential);
    state.token = credential;
    state.subject = claims?.sub;
    state.displayName = claims?.name || claims?.given_name || claims?.email || "";
    sessionStorage.setItem("authsync.idToken", credential);
    localStorage.setItem("authsync.lastSubject", state.subject);
    localStorage.setItem("authsync.displayName", state.displayName);
    clearToast();
    scheduleGoogleSessionExpiry();
    try {
        await registerAppSession();
        await showApp(true);
    } catch(error) {
        signOut(false,error.message||"Sign-in could not be completed.");
    }
    finally { hideLoader(); }
}

async function showApp(afterLogin = false) {
    loadLocalPins();
    try {
        const account = await api("/api/v1/account");
        if (!account.exists) {
            const owner = ownerSubject();
            await LockstepVault.clearSubject(owner);
            localStorage.removeItem(`authsync.lock.${owner}`);
            sessionStorage.removeItem(`authsync.unlocked.${owner}`);
            state.lockConfig = { enabled:false, timeoutSeconds:300, lockOnScreenLock:false };
            state.restoreAuthorized = false;
            sessionStorage.removeItem("authsync.restoreAuthorized");
            if (!afterLogin) {
                signOut(false);
                toast("Your server account no longer exists. Sign in again to start fresh.", true);
                return;
            }
        } else {
            const sharedConfig = await api("/api/v1/lock");
            await LockstepVault.synchronizeWrappedKey(ownerSubject(), sharedConfig.wrappedKey);
            localStorage.setItem(`authsync.lock.${ownerSubject()}`, JSON.stringify(sharedConfig));
            if (await LockstepVault.keyState(ownerSubject()) === "none") {
                state.restoreAuthorized = true;
                sessionStorage.setItem("authsync.restoreAuthorized", "1");
                await syncVault(null,true).catch(() => null);
                showRestore();
                return;
            }
        }
    } catch (error) {
        if (error.code === "SESSION_EXPIRED" || error.code === "ACCOUNT_MISSING") {
            signOut(false);
            toast(error.message, true);
            return;
        }
    }
    let lockConfigLoadedFromServer = false;
    try {
        state.lockConfig = await api("/api/v1/lock");
        lockConfigLoadedFromServer = true;
        localStorage.setItem(`authsync.lock.${ownerSubject()}`, JSON.stringify(state.lockConfig));
    } catch {
        try { state.lockConfig = JSON.parse(localStorage.getItem(`authsync.lock.${ownerSubject()}`)) || { enabled:false, timeoutSeconds:300, lockOnScreenLock:false }; }
        catch { state.lockConfig = { enabled:false, timeoutSeconds:300, lockOnScreenLock:false }; }
    }
    state.lockConfig = normalizeLockConfig(state.lockConfig);
    if (await LockstepVault.keyState(ownerSubject()) === "wrapped" && !state.lockConfig.enabled) {
        state.lockConfig = { ...state.lockConfig, enabled: true };
    }
    updateLockSummary();
    if (await LockstepVault.keyState(ownerSubject()) === "none" && state.lockConfig.enabled) {
        state.restoreAuthorized = true;
        sessionStorage.setItem("authsync.restoreAuthorized", "1");
        showRestore();
        return;
    }
    if (state.lockConfig.enabled) {
        if (await resumeUnlockedSession()) { await showUnlockedApp(); return; }
        showLocked(); return;
    }
    if (!lockConfigLoadedFromServer) {
        signOut(false);
        toast("Sign in again to create lock protection.", true);
        return;
    }
    await showUnlockedApp(false);
    await openLockSettings({ required: true, refresh: false });
}

async function showUnlockedApp(loadVault = true) {
    if(loadVault&&state.lockConfig.enabled&&state.subject&&!LockstepVault.isUnlocked(state.subject)){showLocked();return;}
    el("signed-out").classList.add("hidden");
    el("locked").classList.add("hidden");
    el("restore").classList.add("hidden");
    el("signed-in").classList.remove("hidden");
    el("welcome-message").textContent = state.displayName ? `Welcome, ${state.displayName}` : "Welcome";
    animateIn(el("signed-in"));
    el("sign-out").classList.remove("hidden");
    el("google-sign-in").classList.add("hidden");
    el("open-settings").classList.remove("hidden");
    el("lock-now").classList.toggle("hidden", !state.lockConfig.enabled);
    recordUserActivity();
    if (loadVault) { renderEntrySkeleton(); await loadEntries(); }
}

function showLocked() {
    const entering = el("locked").classList.contains("hidden");
    stopInactivityWatch();
    state.entries=[]; el("entries").innerHTML="";
    el("signed-out").classList.add("hidden"); el("signed-in").classList.add("hidden"); el("restore").classList.add("hidden");
    el("locked").classList.remove("hidden");
    if (entering) animateIn(el("locked"));
    el("sign-out").classList.remove("hidden"); el("open-settings").classList.remove("hidden"); el("lock-now").classList.add("hidden");
    el("google-sign-in").classList.add("hidden");
    el("unlock-passcode").value = ""; hideInlineError("unlock-error");
    if (entering) el("unlock-passcode").focus();
}

function openSettings() {
    if (!state.subject) return;
    const unlocked = Boolean(state.subject && LockstepVault.isUnlocked(state.subject));
    document.querySelectorAll(".vault-setting").forEach(node => node.classList.toggle("hidden", !unlocked));
    el("settings-dialog").showModal();
}

function showRestore(returnView = "signed-out") {
    stopInactivityWatch();
    state.restoreReturnView = returnView;
    el("signed-out").classList.add("hidden");
    el("signed-in").classList.add("hidden");
    el("locked").classList.add("hidden");
    el("restore").classList.remove("hidden");
    el("google-sign-in").classList.add("hidden");
    el("sign-out").classList.add("hidden");
    el("open-settings").classList.add("hidden");
    el("lock-now").classList.add("hidden");
    el("restore-form").reset();
    el("restore-file-name").textContent = "";
    hideInlineError("restore-error");
    animateIn(el("restore"));
    el("restore-key").focus();
}

async function loadRecoveryKeyFile(event) {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
        const match = (await file.text()).match(/LS2-M-[A-Za-z0-9_-]{43}/);
        if (!match) throw new Error("The selected file does not contain a Lockstep recovery key.");
        el("restore-key").value = match[0];
        el("restore-file-name").textContent = file.name;
        hideInlineError("restore-error");
    } catch (error) {
        if (error.code === "SESSION_EXPIRED" || error.code === "ACCOUNT_MISSING") signOut(false, error.message);
        else showInlineError("restore-error", error.message);
    }
}

async function restoreVault(event) {
    event.preventDefault();
    hideInlineError("restore-error");
    const recoveryKey = el("restore-key").value.trim();
    const passcode = el("restore-passcode").value;
    if (!recoveryKey) { showInlineError("restore-error", "Paste a recovery key or choose your downloaded recovery-key file."); return; }
    if (passcode.length < 4) { showInlineError("restore-error", "Passkey must contain at least 4 characters."); return; }
    if (passcode !== el("restore-passcode-confirm").value) { showInlineError("restore-error", "Passkeys do not match."); return; }
    try {
        await syncVault();
        const version = await LockstepVault.importRecoveryKey(ownerSubject(), recoveryKey, passcode);
        const wrappedKey = await LockstepVault.exportWrappedKey(ownerSubject());
        state.lockConfig = await api("/api/v1/lock", { method:"PUT", body:JSON.stringify({ passcode, timeoutSeconds:300, lockOnScreenLock:false, wrappedKey }) });
        localStorage.setItem(`authsync.lock.${ownerSubject()}`, JSON.stringify(state.lockConfig));
        state.restoreAuthorized = false;
        sessionStorage.removeItem("authsync.restoreAuthorized");
        sessionStorage.setItem(lockTimestampKey(), String(Date.now()));
        clearToast();
        await showUnlockedApp(true);
        toast(`Vault restored with encryption key version ${version}`);
    } catch (error) {
        if (error.code === "SESSION_EXPIRED" || error.code === "ACCOUNT_MISSING") signOut(false, error.message);
        else showInlineError("restore-error", error.message);
    }
}

async function resetVault() {
    const confirmed = await confirmAction({ title:"Reset vault?", message:"This permanently deletes all authenticator accounts and vault data from this browser and Firestore. This cannot be undone.", label:"Reset", iconName:"trash", danger:true });
    if (!confirmed) return;
    try {
        const owner = ownerSubject();
        await api("/api/v1/vault", { method:"DELETE" });
        await LockstepVault.clearSubject(owner);
        localStorage.removeItem(`authsync.lock.${owner}`);
        sessionStorage.removeItem(`authsync.unlocked.${owner}`);
        signOut(false, "Vault reset. Sign in again to create lock protection.");
    } catch (error) { showInlineError("restore-error", error.message); }
}

function signOut(showMessage = false, message = "Signed out securely") {
    stopScreenLockWatch();
    stopInactivityWatch();
    stopPendingSyncRetry();
    cancelVaultOperations();
    closeVaultSurfaces();
    clearTimeout(state.tokenExpiryTimer);state.tokenExpiryTimer=null;
    if (el("settings-dialog").open) el("settings-dialog").close();
    if (state.subject) LockstepVault.lock(state.subject);
    const owner=state.subject||tokenClaims(state.token)?.sub||null;
    const unlockKey = state.token || state.subject ? lockTimestampKey() : null;
    const sessionKey = state.token || state.subject ? sessionKeyStorageKey() : null;
    state.token = null;
    state.subject = null;
    state.entries = [];
    state.editing = false;
    sessionStorage.removeItem("authsync.idToken");
    localStorage.removeItem("authsync.idToken");
    sessionStorage.removeItem("authsync.restoreAuthorized");
    state.restoreAuthorized = false;
    localStorage.removeItem("authsync.lastSubject");
    localStorage.removeItem("authsync.displayName");
    if(owner){localStorage.removeItem(`authsync.appSession.web.${owner}`);localStorage.removeItem(`authsync.appSessionExpiry.web.${owner}`);}
    state.displayName = "";
    if (unlockKey) sessionStorage.removeItem(unlockKey);
    if (sessionKey) sessionStorage.removeItem(sessionKey);
    window.google?.accounts?.id?.disableAutoSelect();
    el("signed-out").classList.remove("hidden");
    if (showMessage) animateIn(el("signed-out"));
    el("signed-in").classList.add("hidden");
    el("locked").classList.add("hidden");
    el("restore").classList.add("hidden");
    el("sign-out").classList.add("hidden");
    el("google-sign-in").classList.remove("hidden");
    el("open-settings").classList.add("hidden");
    el("lock-now").classList.add("hidden");
    if (showMessage || message !== "Signed out securely") toast(message, message !== "Signed out securely");
}

async function authenticatedFetch(path, options = {}) {
    if(state.subject&&appSessionHasExpired()){
        const error=new Error("Your 30-day Lockstep session has expired. Sign in with Google again.");
        error.code="SESSION_EXPIRED";
        signOut(false,error.message);
        throw error;
    }
    const appSession=appSessionToken();
    const googleToken=state.token&&!isExpired(state.token)?state.token:"";
    const response = await fetch(apiUrl(path), {
        ...options, cache: "no-store",
        signal: options.signal || state.vaultRequests.signal,
        headers: { "Content-Type":"application/json", ...(googleToken?{Authorization:`Bearer ${googleToken}`}:{"X-Lockstep-Subject":state.subject}), "X-Lockstep-Client":"web", ...(appSession?{"X-Lockstep-Session":appSession}:{}), ...options.headers }
    });
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        const error = new Error(body.error || (response.status === 401 ? "Session expired. Sign in with Google again." : `Request failed (${response.status})`));
        error.code = body.code || (response.status === 401 ? "SESSION_EXPIRED" : "REQUEST_FAILED");
        if(error.code==="SESSION_REVOKED")showSessionRevoked(error.message);
        else if(error.code==="SESSION_EXPIRED")signOut(false,error.message);
        throw error;
    }
    return response;
}

function appSessionStorageKey(subject=ownerSubject()) { return `authsync.appSession.web.${subject}`; }
function appSessionExpiryStorageKey(subject=ownerSubject()) { return `authsync.appSessionExpiry.web.${subject}`; }
function appSessionHasExpired(subject=state.subject){
    if(!subject)return false;
    try{
        const token=localStorage.getItem(appSessionStorageKey(subject));
        const expiresAt=Number(localStorage.getItem(appSessionExpiryStorageKey(subject))||0);
        return Boolean(token)&&(!expiresAt||expiresAt<=Date.now());
    }catch{return false;}
}
function appSessionToken() {
    try{
        const token=localStorage.getItem(appSessionStorageKey())||"";
        const expiresAt=Number(localStorage.getItem(appSessionExpiryStorageKey())||0);
        return token&&expiresAt>Date.now()?token:"";
    }catch{return "";}
}
async function ensureAppSession() {
    return appSessionToken() || registerAppSession();
}
async function registerAppSession() {
    if(!state.token)throw new Error("Sign in with Google first.");
    const response=await fetch(apiUrl("/api/v1/session"),{
        method:"POST",cache:"no-store",
        headers:{"Content-Type":"application/json",Authorization:`Bearer ${state.token}`,"X-Lockstep-Client":"web"}
    });
    const body=await response.json().catch(()=>({}));
    if(!response.ok||!body.sessionToken){
        const error=new Error(body.error||(response.status===401?"Google session expired. Sign in again.":`Request failed (${response.status})`));
        error.code=body.code||(response.status===401?"SESSION_EXPIRED":"REQUEST_FAILED");
        throw error;
    }
    localStorage.setItem(appSessionStorageKey(),body.sessionToken);
    if(body.expiresAtEpochMillis)localStorage.setItem(appSessionExpiryStorageKey(),String(body.expiresAtEpochMillis));
    return body.sessionToken;
}

async function api(path, options = {}) {
    const response = await authenticatedFetch(path, options);
    return response.status === 204 ? null : response.json();
}

function ownerSubject() {
    const subject = tokenClaims(state.token)?.sub || state.subject;
    if (!subject) throw new Error("Sign in to open this authenticator vault.");
    return subject;
}

function vaultLockedError() { const error=new Error("Vault locked. Unlock it to continue.");error.code="VAULT_LOCKED";return error; }
function isVaultLockedError(error) { return error?.code==="VAULT_LOCKED"||error?.name==="AbortError"&&!isVaultOperational(); }
function isVaultOperational() { return Boolean(state.subject&&LockstepVault.isUnlocked(state.subject)&&el("locked").classList.contains("hidden")&&!el("signed-in").classList.contains("hidden")); }
function beginVaultOperation() { enforceCurrentScreenLock();enforceInactivityLock();if(!isVaultOperational())throw vaultLockedError();return state.vaultEpoch; }
function assertVaultOperation(epoch) { if(epoch!==state.vaultEpoch||!isVaultOperational())throw vaultLockedError(); }
function cancelVaultOperations(abortRequests = true) { state.vaultEpoch++;if(abortRequests){state.vaultRequests.abort();state.vaultRequests=new AbortController();}state.refreshing=false; }
function closeVaultSurfaces() {
    stopCameraScanner();clearDragState();state.editing=false;
    ["add-dialog","manual-dialog","uri-dialog","settings-dialog","qr-dialog","camera-dialog","confirm-dialog","lock-dialog"].forEach(id=>{const dialog=el(id);if(dialog?.open)dialog.close("cancel");});
    ["qr-file","backup-file"].forEach(id=>{const input=el(id);if(input)input.value="";});
    el("view-tools")?.classList.remove("hidden");el("edit-tools")?.classList.add("hidden");document.body.classList.remove("editing");clearToast();
}
function scheduleGoogleSessionExpiry() {
    clearTimeout(state.tokenExpiryTimer);state.tokenExpiryTimer=null;
    const expiresAt=Number(tokenClaims(state.token)?.exp||0)*1000;
    if(!expiresAt)return;
    const remaining=expiresAt-Date.now();
    if(remaining<=0){expireGoogleCredential();return;}
    state.tokenExpiryTimer=setTimeout(expireGoogleCredential,remaining);
}
function expireGoogleCredential(){state.token=null;sessionStorage.removeItem("authsync.idToken");if(!state.subject||!appSessionToken())signOut(false,"Session expired. Sign in with Google again.");}

function vaultTransport() {
    return {
        list: () => api("/api/v1/entries"),
        put: (id, payload) => api(`/api/v1/entries/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
        delete: (id) => api(`/api/v1/entries/${id}`, { method: "DELETE" })
    };
}

async function flushPendingVault(owner = state.subject) {
    if(!owner||!appSessionToken())return null;
    try{return await LockstepVault.flushOutbox(owner,vaultTransport());}
    catch(error){if(error.code==="SESSION_EXPIRED")signOut(false,error.message);return null;}
}

function stopPendingSyncRetry() {
    if(state.pendingSyncTimer!==null)clearTimeout(state.pendingSyncTimer);
    state.pendingSyncTimer=null;
    state.pendingSyncRequested=false;
}

function schedulePendingSync(delay = 0) {
    if(state.pendingSyncRunning){state.pendingSyncRequested=true;return;}
    if(state.pendingSyncTimer!==null||!navigator.onLine||!state.subject||!appSessionToken())return;
    state.pendingSyncTimer=setTimeout(runPendingSyncRetry,delay);
}

async function runPendingSyncRetry() {
    state.pendingSyncTimer=null;
    if(state.pendingSyncRunning||!navigator.onLine||!state.subject||!appSessionToken())return;
    state.pendingSyncRunning=true;
    state.pendingSyncRequested=false;
    let pending=0;
    try {
        const owner=state.subject;
        await flushPendingVault(owner);
        pending=await LockstepVault.pendingCount(owner);
        state.pendingChanges=pending;
    } catch { pending=1; }
    finally {
        state.pendingSyncRunning=false;
        if((pending>0||state.pendingSyncRequested)&&navigator.onLine&&state.subject&&appSessionToken())schedulePendingSync(pending>0?10000:0);
    }
}

async function syncVault(epoch = null, allowLockedPull = false) {
    if(epoch!==null)assertVaultOperation(epoch);
    const owner = ownerSubject();
    const account = await api("/api/v1/account");
    if(epoch!==null)assertVaultOperation(epoch);
    if (!account.exists) {
        await LockstepVault.clearSubject(owner);
        localStorage.removeItem(`authsync.lock.${owner}`);
        const error = new Error("Your server account no longer exists. Sign in again to start fresh.");
        error.code = "ACCOUNT_MISSING";
        throw error;
    }
    const result=await LockstepVault.synchronize(owner, vaultTransport(),allowLockedPull);
    if(epoch!==null)assertVaultOperation(epoch);
    return result;
}

function renderEntrySkeleton(count = 4) {
    const entriesEl = el("entries");
    entriesEl.innerHTML = Array.from({ length: count }, () => `
        <article class="entry entry-skel" aria-hidden="true">
            <div class="entry-view">
                <div class="entry-heading"><div><div class="skel-entry-issuer"></div><div class="skel-entry-account"></div></div></div>
                <div class="skel-entry-code"></div>
            </div>
        </article>`).join("");
    el("empty-state").classList.add("hidden");
    el("account-summary").textContent = "";
}

async function loadEntries(force = false) {
    if (state.refreshing || state.editing && !force) return;
    if(!isVaultOperational()){if(state.subject&&state.lockConfig.enabled&&!LockstepVault.isUnlocked(state.subject))showLocked();return;}
    let epoch;
    try{epoch=beginVaultOperation();}
    catch(error){if(isVaultLockedError(error)){showLocked();return;}throw error;}
    state.refreshing = true;
    const hasSkeleton = el("entries").querySelector(".entry-skel") !== null;
    const isEmpty = el("entries").innerHTML.trim() === "";
    if (hasSkeleton || isEmpty) renderEntrySkeleton();
    try {
        try { await syncVault(epoch); assertVaultOperation(epoch);state.offline = false; state.lastSyncError = null; }
        catch (error) {
            if(isVaultLockedError(error))throw error;
            if (error.code === "SESSION_EXPIRED" || error.code === "ACCOUNT_MISSING") {
                signOut(false, error.message);
                return;
            }
            state.offline = true;
            state.lastSyncError = error.message;
        }
        assertVaultOperation(epoch);state.pendingChanges = await LockstepVault.pendingCount(ownerSubject());assertVaultOperation(epoch);
        const loaded = await LockstepVault.listEntries(ownerSubject());
        assertVaultOperation(epoch);
        state.entries = loaded.map((entry) => ({ ...entry, pinned: state.pinnedIds.has(entry.id) }));
        sortLocalPins();
        state.serverOffsetMillis = 0;
        renderEntries();
        if (state.offline) el("account-summary").textContent += ` · Sync failed: ${state.lastSyncError || "Offline"}${state.pendingChanges ? ` · ${state.pendingChanges} change${state.pendingChanges === 1 ? "" : "s"} pending` : ""}`;
    } catch (error) {
        if(isVaultLockedError(error)){showLocked();return;}
        toast(error.message, true);
        if (hasSkeleton || isEmpty) el("entries").innerHTML = "";
    } finally {
        state.refreshing = false;
    }
}

function renderEntries() {
    document.body.classList.toggle("editing", state.editing);
    el("empty-state").classList.toggle("hidden", state.entries.length !== 0 || state.editing);
    el("account-summary").textContent = `${state.entries.length} synchronized account${state.entries.length === 1 ? "" : "s"}`;
    el("entries").innerHTML = state.entries.map((entry, index) => `
        <article class="entry" data-id="${entry.id}">
            <div class="entry-view">
                <div class="entry-heading"><div><p class="issuer">${escapeHtml(entry.issuer)}</p><p class="account">${escapeHtml(entry.accountName)}</p></div>${entry.pinned ? `<span class="pinned-label">${icon("pin")} Pinned</span>` : ""}</div>
                <div class="code-row"><button class="code" data-action="copy" title="Copy code">${formatCode(entry.code)}</button><span class="countdown"></span></div>
                <div class="card-actions"><button data-action="qr" aria-label="Show QR code" title="Show QR code">${icon("qr")}</button><button class="pin-action ${entry.pinned ? "active" : ""}" data-action="pin" aria-label="${entry.pinned ? "Unpin" : "Pin"}" title="${entry.pinned ? "Unpin" : "Pin"}">${icon("pin")}</button></div>
            </div>
            <div class="entry-edit">
                <button class="delete-action" data-action="delete" aria-label="Remove account" title="Remove account">${icon("trash")}</button>
                <div class="edit-fields"><label><span>Issuer</span><input data-field="issuer" maxlength="128" value="${escapeAttribute(entry.issuer)}"></label><label><span>Account</span><input data-field="accountName" maxlength="256" value="${escapeAttribute(entry.accountName)}"></label></div>
                <div class="order-actions"><button data-action="move-up" ${index === 0 ? "disabled" : ""} aria-label="Move up">${icon("up")}</button><button data-action="move-down" ${index === state.entries.length - 1 ? "disabled" : ""} aria-label="Move down">${icon("down")}</button><button class="drag-handle" draggable="true" aria-label="Drag to reorder" title="Drag to reorder">${icon("grip")}</button></div>
            </div>
            <span class="progress"></span>
        </article>`).join("");
    tick();
}

function tick() {
    const serverNow = Date.now() + state.serverOffsetMillis;
    let expired = false;
    document.querySelectorAll(".entry").forEach((node) => {
        const entry = state.entries.find((item) => item.id === node.dataset.id);
        if (!entry) return;
        const remaining = Math.max(0, entry.validUntilEpochMillis - serverNow);
        node.classList.toggle("expiring", remaining > 0 && remaining <= EXPIRING_THRESHOLD_MILLIS);
        node.querySelector(".countdown").textContent = `${Math.ceil(remaining / 1000)}s`;
        node.querySelector(".progress").style.transform = `scaleX(${remaining / (entry.period * 1000)})`;
        if (remaining === 0) expired = true;
    });
    if (expired && (state.token || state.subject) && !state.refreshing && !state.editing && !el("signed-in").classList.contains("hidden")) loadEntries();
}

async function handleEntryClick(event) {
    try{beginVaultOperation();}catch{return;}
    const button = event.target.closest("[data-action]");
    const card = event.target.closest(".entry");
    if (!button || !card) return;
    const entry = state.entries.find((item) => item.id === card.dataset.id);
    if (!entry) return;
    const action = button.dataset.action;
    if (action === "copy") {
        await navigator.clipboard.writeText(entry.code);
        toast("Code copied");
    } else if (action === "qr") await showQr(entry);
    else if (action === "pin") await togglePin(entry.id);
    else if (action === "move-up") moveEntry(entry.id, -1);
    else if (action === "move-down") moveEntry(entry.id, 1);
    else if (action === "delete") await deleteEntry(entry);
}

async function togglePin(id) {
    try{beginVaultOperation();}catch{return;}
    syncDraftsFromInputs();
    const positions = capturePositions();
    const entry = state.entries.find((item) => item.id === id);
    entry.pinned = !entry.pinned;
    if (entry.pinned) state.pinnedIds.add(id); else state.pinnedIds.delete(id);
    saveLocalPins();
    sortLocalPins();
    renderEntries();
    animateReorder(positions, id);
}

function sortLocalPins() {
    const ranks = new Map(state.entryOrder.map((id, index) => [id, index]));
    state.entries.sort((a, b) => Number(b.pinned) - Number(a.pinned)
        || (ranks.get(a.id) ?? Number.MAX_SAFE_INTEGER) - (ranks.get(b.id) ?? Number.MAX_SAFE_INTEGER)
        || (a.createdAtEpochMillis ?? 0) - (b.createdAtEpochMillis ?? 0));
    state.entryOrder = state.entries.map((entry) => entry.id);
}
function pinStorageKey() { return `authsync.pins.${ownerSubject()}`; }
function orderStorageKey() { return `authsync.order.${ownerSubject()}`; }
function loadLocalPins() {
    try { state.pinnedIds = new Set(JSON.parse(localStorage.getItem(pinStorageKey()) || "[]")); } catch { state.pinnedIds = new Set(); }
    try { state.entryOrder = JSON.parse(localStorage.getItem(orderStorageKey()) || "[]"); } catch { state.entryOrder = []; }
    if (!Array.isArray(state.entryOrder)) state.entryOrder = [];
}
function saveLocalPins() { localStorage.setItem(pinStorageKey(), JSON.stringify([...state.pinnedIds])); }
function saveLocalOrder() { state.entryOrder = state.entries.map((entry) => entry.id); localStorage.setItem(orderStorageKey(), JSON.stringify(state.entryOrder)); }

function setEditing(value) {
    if(value){try{beginVaultOperation();}catch{return;}}
    state.editing = value;
    if (value) state.originals = new Map(state.entries.map((entry) => [entry.id, { ...entry }]));
    el("view-tools").classList.toggle("hidden", value);
    el("edit-tools").classList.toggle("hidden", !value);
    renderEntries();
}

async function saveEdits() {
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    syncDraftsFromInputs();
    if (state.entries.some((entry) => !entry.issuer.trim() || !entry.accountName.trim())) { toast("Issuer and account name are required", true); return; }
    el("save-edits").disabled = true;
    try {
        for (const entry of state.entries) {
            assertVaultOperation(epoch);
            const original = state.originals.get(entry.id);
            if (!original || original.issuer !== entry.issuer.trim() || original.accountName !== entry.accountName.trim()) {
                const owner=ownerSubject();
                await LockstepVault.updateEntry(owner, entry.id, entry.issuer.trim(), entry.accountName.trim());
                schedulePendingSync(0);
                if(!isVaultOperational()){void flushPendingVault(owner);throw vaultLockedError();}
                assertVaultOperation(epoch);
            }
        }
        assertVaultOperation(epoch);
        saveLocalOrder();
        await syncVault(epoch).catch(error=>{if(isVaultLockedError(error))throw error;});
        assertVaultOperation(epoch);
        state.editing = false;
        el("view-tools").classList.remove("hidden");
        el("edit-tools").classList.add("hidden");
        await loadEntries(true);
        toast("Changes saved");
    } catch (error) { if(!isVaultLockedError(error))toast(error.message, true); }
    finally { el("save-edits").disabled = false; }
}

function syncDraftsFromInputs() {
    document.querySelectorAll(".entry").forEach((card) => {
        const entry = state.entries.find((item) => item.id === card.dataset.id);
        if (!entry) return;
        const issuer = card.querySelector('[data-field="issuer"]');
        const account = card.querySelector('[data-field="accountName"]');
        if (issuer) entry.issuer = issuer.value;
        if (account) entry.accountName = account.value;
    });
}

function moveEntry(id, direction) {
    try{beginVaultOperation();}catch{return;}
    syncDraftsFromInputs();
    const from = state.entries.findIndex((entry) => entry.id === id);
    const to = from + direction;
    if (to < 0 || to >= state.entries.length) return;
    if (state.entries[from].pinned !== state.entries[to].pinned) { toast("Pinned accounts stay together at the top"); return; }
    const positions = capturePositions();
    const [moved] = state.entries.splice(from, 1);
    state.entries.splice(to, 0, moved);
    renderEntries();
    animateReorder(positions, id);
}

function handleDragStart(event) {
    try{beginVaultOperation();}catch{event.preventDefault();return;}
    const handle = event.target.closest(".drag-handle");
    const card = handle?.closest(".entry");
    if (!state.editing || !card) { event.preventDefault(); return; }
    syncDraftsFromInputs();
    state.dragId = card.dataset.id;
    card.classList.add("dragging");
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", state.dragId);
}
function handleDragOver(event) { if (state.dragId && event.target.closest(".entry")) event.preventDefault(); }
function handleDrop(event) {
    const target = event.target.closest(".entry");
    if (!target || !state.dragId || target.dataset.id === state.dragId) return;
    event.preventDefault();
    const source = state.entries.findIndex((entry) => entry.id === state.dragId);
    let destination = state.entries.findIndex((entry) => entry.id === target.dataset.id);
    if (state.entries[source].pinned !== state.entries[destination].pinned) { toast("Pinned accounts stay together at the top"); clearDragState(); return; }
    const positions = capturePositions();
    const [moved] = state.entries.splice(source, 1);
    destination = state.entries.findIndex((entry) => entry.id === target.dataset.id);
    if (event.clientY > target.getBoundingClientRect().top + target.offsetHeight / 2) destination++;
    state.entries.splice(destination, 0, moved);
    clearDragState(); renderEntries(); animateReorder(positions, moved.id);
}
function clearDragState() { state.dragId = null; document.querySelectorAll(".dragging").forEach((node) => node.classList.remove("dragging")); }
function capturePositions() { return new Map([...document.querySelectorAll(".entry")].map((node) => [node.dataset.id, node.getBoundingClientRect()])); }
function animateReorder(previous, highlightedId) {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    document.querySelectorAll(".entry").forEach((node) => {
        const old = previous.get(node.dataset.id); if (!old) return;
        const now = node.getBoundingClientRect(), x = old.left - now.left, y = old.top - now.top;
        const highlighted = node.dataset.id === highlightedId;
        if (Math.abs(x) < 1 && Math.abs(y) < 1) { if (highlighted) node.animate([{ transform:"scale(1)" },{ transform:"scale(1.018)" },{ transform:"scale(1)" }],{ duration:300,easing:"ease-out" }); return; }
        node.animate([{ transform:`translate(${x}px,${y}px)` },{ transform:"translate(0,0)" }],{ duration:highlighted ? 440 : 360,easing:"cubic-bezier(.22,.72,.18,1)" });
    });
}

async function deleteEntry(entry) {
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    const confirmed = await confirmAction({ title:"Remove account?", message:`${entry.issuer} (${entry.accountName}) will be removed from every synchronized device.`, label:"Remove", iconName:"trash", danger:true });
    if (!confirmed) return;
    try {
        assertVaultOperation(epoch);
        const owner=ownerSubject();
        await LockstepVault.deleteEntry(owner, entry.id);
        schedulePendingSync(0);
        if(!isVaultOperational()){void flushPendingVault(owner);throw vaultLockedError();}
        assertVaultOperation(epoch);
        await syncVault(epoch).catch(error=>{if(isVaultLockedError(error))throw error;});
        assertVaultOperation(epoch);
        state.pinnedIds.delete(entry.id); saveLocalPins();
        state.entries = state.entries.filter((item) => item.id !== entry.id);
        saveLocalOrder();
        renderEntries(); toast("Account removed");
    } catch (error) { if(!isVaultLockedError(error))toast(error.message, true); }
}

function openAdd() { try{beginVaultOperation();}catch{return;}hideInlineError("add-error");updateLiveScanCopy();el("add-dialog").showModal(); }
function closeAdd() { hideInlineError("add-error"); el("add-dialog").close(); }
function openSubDialog(id) { try{beginVaultOperation();}catch{return;}el("add-dialog").close(); el(id).showModal(); }

async function addOtpUri(otpAuthUri) {
    const epoch=beginVaultOperation(),owner=ownerSubject();
    await LockstepVault.addOtpUri(owner, otpAuthUri);
    schedulePendingSync(0);
    if(!isVaultOperational()){void flushPendingVault(owner);throw vaultLockedError();}
    assertVaultOperation(epoch);
    await syncVault(epoch).catch(error=>{if(isVaultLockedError(error))throw error;});
    assertVaultOperation(epoch);
}

async function addManualEntry(event) {
    event.preventDefault(); hideInlineError("manual-error");
    const issuer=el("manual-issuer").value.trim(), account=el("manual-account").value.trim()||nextDefaultAccountName(state.entries);
    const secret=el("manual-secret").value.toUpperCase().replace(/[\s-]/g,"");
    if(!/^[A-Z2-7]+=*$/.test(secret)){showInlineError("manual-error","Secret must contain valid Base32 characters (A-Z and 2-7).");return;}
    const period=Number(el("manual-period").value);
    const query=new URLSearchParams({secret,issuer,algorithm:el("manual-algorithm").value,digits:el("manual-digits").value,period:String(period)});
    const uri=`otpauth://totp/${encodeURIComponent(`${issuer}:${account}`)}?${query}`;
    try{await addOtpUri(uri);if(!isVaultOperational())return;el("manual-form").reset();el("manual-period").value="30";el("manual-dialog").close();await loadEntries(true);if(isVaultOperational())toast("Authenticator added");}
    catch(error){if(!isVaultLockedError(error))showInlineError("manual-error",error.message);}
}

async function importOtpUrls(event) {
    event.preventDefault(); hideInlineError("uri-error");
    try{beginVaultOperation();const uris=parseBackup(el("otp-uris").value);const result=await importUris(uris);if(!isVaultOperational())return;el("uri-form").reset();el("uri-dialog").close();await loadEntries(true);if(isVaultOperational())toast(result.failed?`${result.imported} imported; ${result.failed} failed`:`${result.imported} account${result.imported===1?"":"s"} imported`,result.failed>0);}
    catch(error){if(!isVaultLockedError(error))showInlineError("uri-error",error.message);}
}
async function openCameraScanner() {
    try{beginVaultOperation();}catch{return;}
    closeAdd();
    const dialog=el("camera-dialog");
    cameraScanner.source=isMobileScannerDevice()?"camera":"screen";
    const screen=cameraScanner.source==="screen";
    dialog.removeAttribute("data-display-surface");
    dialog.classList.toggle("screen-source",screen);
    el("scanner-kicker").textContent=screen?"SCREEN SCANNER":"LIVE SCANNER";
    el("scanner-title").textContent=screen?"Scan QR from your screen":"Scan authenticator QR";
    el("scanner-description").textContent=screen?"In the share picker, choose Browser tab (or Chrome tab), then select this tab or another tab containing the QR code.":"The account is added automatically when the code is detected.";
    hideInlineError("camera-error");
    el("retry-camera").classList.add("hidden");
    clearScreenSelection();
    el("camera-status").textContent=screen?"Select this tab or another tab in the browser share picker. Then drag around the QR code in this preview.":"Point the camera at a TOTP QR code.";
    el("camera-starting").classList.remove("hidden");
    dialog.showModal();
    await startCameraStream();
}

function isMobileScannerDevice() {
    if(typeof navigator.userAgentData?.mobile==="boolean")return navigator.userAgentData.mobile;
    return /Android|iPhone|iPad|iPod|IEMobile|Mobile/i.test(navigator.userAgent)
        || /Macintosh/i.test(navigator.userAgent)&&navigator.maxTouchPoints>1;
}

function updateLiveScanCopy() {
    const mobile=isMobileScannerDevice();
    el("live-scan-label").textContent=mobile?"Scan with camera":"Scan from screen";
    el("live-scan-description").textContent=mobile?"Point your camera at an authenticator QR":"Select this tab or another tab containing the QR";
}

async function startCameraStream() {
    try{beginVaultOperation();}catch{if(el("camera-dialog").open)el("camera-dialog").close();return;}
    stopCameraScanner();
    hideInlineError("camera-error");
    el("retry-camera").classList.add("hidden");
    const screen=cameraScanner.source==="screen";
    el("camera-starting").textContent=screen?"Waiting for screen selection…":"Starting camera…";
    el("camera-starting").classList.remove("hidden");
    if (typeof window.jsQR !== "function") {
        showCameraError("The QR scanner could not be loaded. Refresh the page or import a saved QR image.");
        return;
    }
    const capture=screen?navigator.mediaDevices?.getDisplayMedia:navigator.mediaDevices?.getUserMedia;
    if (!capture) {
        showCameraError(screen?"Screen scanning is not supported in this browser. Import a saved QR image instead.":"Live camera scanning is not supported in this browser. Import a saved QR image instead.");
        return;
    }
    try {
        const stream=screen
            ? await navigator.mediaDevices.getDisplayMedia({
                audio:false,
                video:{displaySurface:"browser",frameRate:{ideal:10,max:15}},
                preferCurrentTab:false,
                selfBrowserSurface:"include",
                surfaceSwitching:"include",
                monitorTypeSurfaces:"include",
                systemAudio:"exclude"
            })
            : await navigator.mediaDevices.getUserMedia({audio:false,video:{facingMode:{ideal:"environment"},width:{ideal:1280},height:{ideal:720}}});
        cameraScanner.stream=stream;
        if(screen){
            const track=stream.getVideoTracks()[0];
            el("camera-dialog").dataset.displaySurface=track?.getSettings?.().displaySurface||"unknown";
            track?.addEventListener("ended",()=>{if(cameraScanner.stream===stream&&el("camera-dialog").open)showCameraError("Screen sharing stopped. Choose a screen, window, or tab to try again.");},{once:true});
        }
        if (!el("camera-dialog").open) { stopCameraScanner(); return; }
        const video=el("camera-video");
        video.srcObject=cameraScanner.stream;
        await video.play();
        cameraScanner.lastScanAt=0;cameraScanner.frameCount=0;cameraScanner.lastValue="";cameraScanner.ignoreUntil=0;
        el("camera-starting").classList.add("hidden");
        if(screen)el("camera-status").textContent="Drag around the QR code you want to scan.";
        recordUserActivity();
        scheduleScannerFrame();
    } catch (error) {
        const denied=error?.name==="NotAllowedError"||error?.name==="SecurityError";
        const missing=error?.name==="NotFoundError"||error?.name==="OverconstrainedError";
        showCameraError(screen?(denied?"Screen sharing was cancelled or blocked. Choose what to share and try again.":"Screen capture could not be started. Try again or import a saved QR image."):(denied?"Camera access was blocked. Allow camera permission and try again.":missing?"No usable camera was found on this device.":"The camera could not be started. Try again or import a saved QR image."));
    }
}

function showCameraError(message) {
    stopCameraScanner();
    el("camera-starting").classList.add("hidden");
    showInlineError("camera-error",message);
    el("retry-camera").classList.remove("hidden");
}

function stopCameraScanner() {
    if(cameraScanner.frameRequest)cancelAnimationFrame(cameraScanner.frameRequest);
    cameraScanner.frameRequest=0;
    if(cameraScanner.frameTimer!==null)clearTimeout(cameraScanner.frameTimer);
    cameraScanner.frameTimer=null;
    const stream=cameraScanner.stream;
    cameraScanner.stream=null;
    stream?.getTracks().forEach(track=>track.stop());
    cameraScanner.processing=false;
    cameraScanner.selection=null;cameraScanner.selectionDrag=null;
    el("screen-selection")?.classList.add("hidden");
    el("clear-screen-selection")?.classList.add("hidden");
    const video=el("camera-video");
    if(video){video.pause();video.srcObject=null;}
}

function screenVideoLayout() {
    const video=el("camera-video"),viewfinder=el("camera-viewfinder"),bounds=viewfinder.getBoundingClientRect();
    if(!video.videoWidth||!video.videoHeight||!video.clientWidth||!video.clientHeight)return null;
    const scale=Math.min(video.clientWidth/video.videoWidth,video.clientHeight/video.videoHeight);
    const width=video.videoWidth*scale,height=video.videoHeight*scale;
    const left=video.offsetLeft+(video.clientWidth-width)/2,top=video.offsetTop+(video.clientHeight-height)/2;
    return{bounds,left,top,width,height};
}

function screenPoint(event) {
    const layout=screenVideoLayout();if(!layout)return null;
    const x=Math.max(0,Math.min(layout.width,event.clientX-layout.bounds.left-layout.left));
    const y=Math.max(0,Math.min(layout.height,event.clientY-layout.bounds.top-layout.top));
    return{layout,x,y};
}

function startScreenSelection(event) {
    if(cameraScanner.source!=="screen"||!cameraScanner.stream||cameraScanner.processing)return;
    const point=screenPoint(event);if(!point)return;
    event.preventDefault();el("camera-viewfinder").setPointerCapture(event.pointerId);
    el("camera-status").classList.remove("is-error");hideInlineError("camera-error");
    cameraScanner.selectionDrag={pointerId:event.pointerId,startX:point.x,startY:point.y,layout:point.layout};
    renderScreenSelection(point.x,point.y,point.x,point.y,point.layout);
}

function moveScreenSelection(event) {
    const drag=cameraScanner.selectionDrag;if(!drag||drag.pointerId!==event.pointerId)return;
    const point=screenPoint(event);if(!point)return;
    renderScreenSelection(drag.startX,drag.startY,point.x,point.y,point.layout);
}

function finishScreenSelection(event) {
    const drag=cameraScanner.selectionDrag;if(!drag||drag.pointerId!==event.pointerId)return;
    const point=screenPoint(event);cameraScanner.selectionDrag=null;
    if(!point){clearScreenSelection();return;}
    const x=Math.min(drag.startX,point.x),y=Math.min(drag.startY,point.y),width=Math.abs(point.x-drag.startX),height=Math.abs(point.y-drag.startY);
    if(width<24||height<24){clearScreenSelection();return;}
    cameraScanner.selection={x:x/point.layout.width,y:y/point.layout.height,width:width/point.layout.width,height:height/point.layout.height};
    renderScreenSelection(x,y,x+width,y+height,point.layout);
    el("clear-screen-selection").classList.remove("hidden");
    el("camera-status").textContent="Scanning the selected area for a TOTP QR code…";
    el("camera-status").classList.remove("is-error");
    cameraScanner.ignoreUntil=0;
    validateScreenSelection();
}

function renderScreenSelection(startX,startY,endX,endY,layout) {
    const selection=el("screen-selection"),x=Math.min(startX,endX),y=Math.min(startY,endY);
    selection.style.left=`${layout.left+x}px`;selection.style.top=`${layout.top+y}px`;
    selection.style.width=`${Math.abs(endX-startX)}px`;selection.style.height=`${Math.abs(endY-startY)}px`;
    selection.classList.remove("hidden");
}

function clearScreenSelection() {
    cameraScanner.selection=null;cameraScanner.selectionDrag=null;
    el("screen-selection")?.classList.add("hidden");
    el("clear-screen-selection")?.classList.add("hidden");
    el("camera-status")?.classList.remove("is-error");
    if(cameraScanner.source==="screen"&&cameraScanner.stream)el("camera-status").textContent="Drag around the QR code you want to scan.";
}

function decodeCameraFrame(selected,inversionAttempts) {
    const video=el("camera-video");
    if(!cameraScanner.stream||video.readyState<2||!video.videoWidth||!video.videoHeight)return null;
    const sourceX=selected?Math.round(selected.x*video.videoWidth):0,sourceY=selected?Math.round(selected.y*video.videoHeight):0;
    const sourceWidth=selected?Math.max(1,Math.round(selected.width*video.videoWidth)):video.videoWidth;
    const sourceHeight=selected?Math.max(1,Math.round(selected.height*video.videoHeight)):video.videoHeight;
    const canvas=el("camera-canvas"),maxDimension=cameraScanner.source==="screen"?1440:720,scale=Math.min(1,maxDimension/Math.max(sourceWidth,sourceHeight));
    const width=Math.max(1,Math.round(sourceWidth*scale)),height=Math.max(1,Math.round(sourceHeight*scale));
    if(canvas.width!==width)canvas.width=width;if(canvas.height!==height)canvas.height=height;
    const context=canvas.getContext("2d",{willReadFrequently:true});
    context.drawImage(video,sourceX,sourceY,sourceWidth,sourceHeight,0,0,canvas.width,canvas.height);
    const pixels=context.getImageData(0,0,canvas.width,canvas.height);
    return window.jsQR?.(pixels.data,pixels.width,pixels.height,{inversionAttempts});
}

function validateScreenSelection() {
    if(!cameraScanner.selection||!cameraScanner.stream||cameraScanner.processing)return;
    cameraScanner.processing=true;
    try {
        const decoded=decodeCameraFrame(cameraScanner.selection,"attemptBoth");
        cameraScanner.processing=false;
        if(decoded?.data){handleCameraResult(decoded.data);return;}
        el("camera-status").textContent="Invalid QR code scanned. Select a valid TOTP QR code and try again.";
        el("camera-status").classList.add("is-error");
        cameraScanner.ignoreUntil=Date.now()+600;
    } catch {
        cameraScanner.processing=false;
        el("camera-status").textContent="Invalid QR code scanned. Select a valid TOTP QR code and try again.";
        el("camera-status").classList.add("is-error");
        cameraScanner.ignoreUntil=Date.now()+600;
    }
}

function scheduleScannerFrame() {
    if(cameraScanner.source==="screen")cameraScanner.frameTimer=setTimeout(()=>scanCameraFrame(performance.now()),240);
    else cameraScanner.frameRequest=requestAnimationFrame(scanCameraFrame);
}

function scanCameraFrame(timestamp) {
    scheduleScannerFrame();
    if(cameraScanner.processing||timestamp-cameraScanner.lastScanAt<240||Date.now()<cameraScanner.ignoreUntil)return;
    if(cameraScanner.source==="screen"&&!cameraScanner.selection)return;
    const video=el("camera-video");
    if(!cameraScanner.stream||video.readyState<2||!video.videoWidth||!video.videoHeight)return;
    cameraScanner.lastScanAt=timestamp;cameraScanner.frameCount++;
    try {
        const selected=cameraScanner.source==="screen"?cameraScanner.selection:null;
        const decoded=decodeCameraFrame(selected,cameraScanner.frameCount%5===0?"attemptBoth":"dontInvert");
        if(decoded?.data)handleCameraResult(decoded.data);
    } catch {
        cameraScanner.ignoreUntil=Date.now()+500;
    }
}

async function handleCameraResult(value) {
    if(value===cameraScanner.lastValue&&Date.now()<cameraScanner.ignoreUntil)return;
    cameraScanner.lastValue=value;
    if(!value.startsWith("otpauth://totp/")){
        el("camera-status").textContent="Invalid QR code scanned. Select a valid TOTP authenticator QR code.";
        el("camera-status").classList.add("is-error");
        cameraScanner.ignoreUntil=Date.now()+1400;
        return;
    }
    cameraScanner.processing=true;cameraScanner.ignoreUntil=Number.POSITIVE_INFINITY;
    el("camera-status").classList.remove("is-error");
    el("camera-status").textContent="QR code found. Adding account…";
    recordUserActivity();
    try {
        await addOtpUri(value);
        if(!isVaultOperational())return;
        el("camera-dialog").close();
        await loadEntries(true);
        toast("Authenticator added");
    } catch(error) {
        if(isVaultLockedError(error))return;
        showInlineError("camera-error",error.message);
        el("camera-status").textContent=cameraScanner.source==="screen"?(cameraScanner.selection?"Adjust the selection or keep the TOTP QR code visible.":"Drag around the QR code to focus scanning."):"Point the camera at a TOTP QR code.";
        cameraScanner.processing=false;cameraScanner.ignoreUntil=Date.now()+1800;
    }
}

async function scanQrImage(event) {
    const files = [...event.target.files]; if (!files.length) return;
    let epoch;try{epoch=beginVaultOperation();}catch{event.target.value="";return;}
    try {
        toast(`Scanning ${files.length===1?"image":`${files.length} images`}…`,false,true);
        const uris=[];
        for(const file of files){assertVaultOperation(epoch);let loaded;try{loaded=await loadQrImage(file);assertVaultOperation(epoch);const uri=detectTotpQr(loaded.source);if(uri)uris.push(uri);}catch(error){if(isVaultLockedError(error))throw error;/* reported as unreadable */}finally{loaded?.close();}await new Promise(requestAnimationFrame);}
        if (!uris.length) throw new Error("No TOTP QR code was found in the selected images.");
        const result=await importUris(uris),unreadable=files.length-uris.length;
        closeAdd();await loadEntries(true);toast(`${result.imported} imported${unreadable?`; ${unreadable} image${unreadable===1?"":"s"} unreadable`:""}`,unreadable>0||result.failed>0);
    } catch (error) { clearToast();if(!isVaultLockedError(error))showInlineError("add-error", error.message); }
    finally { event.target.value = ""; }
}

async function importUris(uris){let imported=0,failed=0;for(const otpAuthUri of uris){try{await addOtpUri(otpAuthUri);imported++;}catch(error){if(isVaultLockedError(error))throw error;failed++;}}return{imported,failed};}
async function loadQrImage(file) {
    if(typeof createImageBitmap==="function"){
        try{
            const bitmap=await createImageBitmap(file,{imageOrientation:"from-image"});
            return{source:bitmap,close:()=>bitmap.close()};
        }catch{/* Fall through for browsers with incomplete createImageBitmap support. */}
    }
    const url=URL.createObjectURL(file),image=new Image();
    try{await new Promise((resolve,reject)=>{image.onload=resolve;image.onerror=()=>reject(new Error("Image could not be read."));image.src=url;});return{source:image,close:()=>URL.revokeObjectURL(url)};}
    catch(error){URL.revokeObjectURL(url);throw error;}
}
function detectTotpQr(image) {
    if (typeof window.jsQR !== "function") throw new Error("The bundled QR decoder could not be loaded.");
    const sourceWidth=image.videoWidth||image.naturalWidth||image.width,sourceHeight=image.videoHeight||image.naturalHeight||image.height;
    if(!sourceWidth||!sourceHeight)throw new Error("The image has no readable dimensions.");
    const maxDimension=1024,scale=Math.min(1,maxDimension/Math.max(sourceWidth,sourceHeight));
    const canvas = document.createElement("canvas"); canvas.width=Math.max(1,Math.round(sourceWidth*scale)); canvas.height=Math.max(1,Math.round(sourceHeight*scale));
    const context=canvas.getContext("2d",{willReadFrequently:true});context.drawImage(image,0,0,sourceWidth,sourceHeight,0,0,canvas.width,canvas.height);
    const pixels=context.getImageData(0,0,canvas.width,canvas.height);
    let decoded=window.jsQR(pixels.data,pixels.width,pixels.height,{inversionAttempts:"dontInvert"});
    if(!decoded)decoded=window.jsQR(pixels.data,pixels.width,pixels.height,{inversionAttempts:"attemptBoth"});
    return decoded?.data?.startsWith("otpauth://totp/") ? decoded.data : null;
}

async function showQr(entry) {
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    el("qr-title").textContent = entry.issuer; el("qr-account").textContent = entry.accountName;
    el("qr-loading").textContent = ""; el("qr-loading").classList.add("hidden"); el("qr-skeleton").classList.remove("hidden"); el("qr-image").classList.add("hidden"); el("qr-dialog").showModal();
    try {
        const uri = await LockstepVault.otpAuthUri(ownerSubject(), entry.id);
        assertVaultOperation(epoch);
        if (!globalThis.QRCode?.toDataURL) throw new Error("The local QR generator is unavailable.");
        const source=await globalThis.QRCode.toDataURL(uri, { errorCorrectionLevel: "M", margin: 2, width: 320 });assertVaultOperation(epoch);el("qr-image").src = source;
        el("qr-skeleton").classList.add("hidden"); el("qr-image").classList.remove("hidden"); el("qr-loading").classList.add("hidden");
    } catch (error) { if(!isVaultLockedError(error)){el("qr-skeleton").classList.add("hidden"); el("qr-loading").textContent = error.message; el("qr-loading").classList.remove("hidden");} }
}
function clearQrDialog() { const source=el("qr-image").src; if(source.startsWith("blob:")) URL.revokeObjectURL(source); el("qr-skeleton").classList.remove("hidden"); el("qr-loading").classList.add("hidden"); el("qr-image").removeAttribute("src"); }

async function exportBackup() {
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    const confirmed = await confirmAction({ title:"Export authenticator backup?", message:"The text file contains the secrets needed to generate every code. Store it somewhere private and never share it.", label:"Export backup", iconName:"export" });
    if (!confirmed) return;
    try {
        assertVaultOperation(epoch);const text=await LockstepVault.exportText(ownerSubject());assertVaultOperation(epoch);const url=URL.createObjectURL(new Blob([text], { type:"text/plain;charset=utf-8" })), link=document.createElement("a");
        link.href=url; link.download=`lockstep-totp-backup-${new Date().toISOString().slice(0,10)}.txt`; link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000); toast("Backup exported");
    } catch(error) { if(!isVaultLockedError(error))toast(error.message,true); }
}

function downloadRecoveryKeyFile(value) {
    const text = `Lockstep recovery key\n\n${value}\n\nKeep this file private. Anyone with this key can restore and decrypt your authenticator vault.\n`;
    const url = URL.createObjectURL(new Blob([text], { type:"text/plain;charset=utf-8" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `lockstep-recovery-key-${new Date().toISOString().slice(0,10)}.txt`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function exportRecoveryKey() {
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    try {
        const config = await api("/api/v1/lock");
        assertVaultOperation(epoch);
        if (await LockstepVault.synchronizeWrappedKey(ownerSubject(), config.wrappedKey)) {
            state.lockConfig = config;
            lockApp();
            toast("The synchronized passkey changed. Unlock again before downloading the recovery key.", true);
            return;
        }
        const recoveryKey=await LockstepVault.exportRecoveryKey(ownerSubject());assertVaultOperation(epoch);downloadRecoveryKeyFile(recoveryKey);
        toast("Recovery key downloaded. Store it somewhere private.");
    } catch (error) { if(!isVaultLockedError(error))toast(error.message, true); }
}

async function rotateEncryptionKey() {
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    const settingsWasOpen = el("settings-dialog").open;
    if (settingsWasOpen) el("settings-dialog").close();
    const confirmed = await confirmAction({ title:"Rotate encryption key?", message:"A brand-new master key is generated and every account is re-encrypted with it. A NEW recovery key will be downloaded; your old recovery key stops working. Other devices pick up the new key the next time they unlock. Enter your passkey to continue.", label:"Rotate key", iconName:"lock", passkey:true });
    const passkey = state.confirmPasskey; state.confirmPasskey = "";
    if (!confirmed) { if (settingsWasOpen) openSettings(); return; }
    if (passkey.length < 4) { toast("Enter your passkey to rotate the encryption key.", true); if (settingsWasOpen) openSettings(); return; }
    toast("Rotating encryption key and synchronizing accounts…", false, true);
    let result = null;
    try {
        assertVaultOperation(epoch);
        const owner = ownerSubject();
        await syncVault(epoch); // must be online and fully synced before the key changes
        assertVaultOperation(epoch);
        const remaining = await LockstepVault.pendingCount(owner);
        assertVaultOperation(epoch);
        if (remaining > 0) throw new Error(`Cannot rotate while ${remaining} change${remaining === 1 ? " is" : "s are"} pending synchronization.`);
        result = await LockstepVault.rotateMasterKey(owner, passkey);
        assertVaultOperation(epoch);
        downloadRecoveryKeyFile(result.recoveryKey); // save the new key before any network call can fail
        // Publish the new wrapped key BEFORE the re-encrypted entries so other devices can always decrypt what they pull.
        state.lockConfig = await api("/api/v1/lock", { method:"PUT", body:JSON.stringify({ passcode:passkey, timeoutSeconds:state.lockConfig.timeoutSeconds || 300, lockOnScreenLock:Boolean(state.lockConfig.lockOnScreenLock), wrappedKey:result.wrappedKey }) });
        assertVaultOperation(epoch);
        localStorage.setItem(`authsync.lock.${owner}`, JSON.stringify(state.lockConfig));
        await syncVault(epoch);
        assertVaultOperation(epoch);
        await loadEntries(true);
        toast(`Key rotated to version ${result.version}. New recovery key downloaded; store it somewhere private.`);
    } catch (error) {
        if(isVaultLockedError(error))return;
        if (result) toast(`Key rotated on this device (version ${result.version}) and the new recovery key was downloaded, but syncing failed: ${error.message} Unlock again to retry.`, true);
        else toast(error.message, true);
    }
}
async function importBackup(event) {
    const file=event.target.files?.[0]; event.target.value=""; if(!file)return;
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    try {
        const uris=parseBackup(await file.text());assertVaultOperation(epoch);toast(`Importing ${uris.length} account${uris.length===1?"":"s"}…`);const {imported,failed}=await importUris(uris);assertVaultOperation(epoch);
        await loadEntries(true); toast(failed?`${imported} imported; ${failed} failed`:`${imported} account${imported===1?"":"s"} imported`,failed>0);
    } catch(error){if(!isVaultLockedError(error))toast(error.message,true);}
}
function parseBackup(text) {
    const uris=text.split(/\r?\n/).map((line)=>line.trim()).filter((line)=>line&&!line.startsWith("#"));
    if(!uris.length)throw new Error("This backup does not contain any TOTP entries."); if(uris.length>500)throw new Error("A backup can contain at most 500 entries.");
    const invalid=uris.findIndex((line)=>!line.startsWith("otpauth://totp/")); if(invalid>=0)throw new Error(`Invalid TOTP URI on backup entry ${invalid+1}.`); return uris;
}
function nextDefaultAccountName(items){const highest=items.reduce((maximum,item)=>{const match=/^Account (\d+)$/.exec(item.accountName||"");return match?Math.max(maximum,Number(match[1])):maximum;},0);return `Account ${highest+1}`;}

function lockTimestampKey(){return `authsync.unlocked.${ownerSubject()}`;}
function sessionKeyStorageKey(){return `authsync.session-key.${ownerSubject()}`;}
function normalizeLockConfig(config){const timeout=Number(config?.timeoutSeconds);return{...(config||{}),enabled:Boolean(config?.enabled),timeoutSeconds:LOCK_TIMEOUT_LABELS.has(timeout)?timeout:300,lockOnScreenLock:Boolean(config?.lockOnScreenLock)};}
function persistUnlockedSession(){
    if(!state.lockConfig.enabled){sessionStorage.removeItem(sessionKeyStorageKey());return;}
    const snapshot=LockstepVault.exportSessionKey(ownerSubject());
    if(snapshot)sessionStorage.setItem(sessionKeyStorageKey(),JSON.stringify(snapshot));
}
async function resumeUnlockedSession(){
    if(!state.lockConfig.enabled)return false;
    const lastActivity=Number(sessionStorage.getItem(lockTimestampKey())||0);
    if(!lastActivity||Date.now()-lastActivity>=state.lockConfig.timeoutSeconds*1000){clearUnlockedSession();return false;}
    if(!LockstepVault.isUnlocked(ownerSubject())){
        try{
            const snapshot=JSON.parse(sessionStorage.getItem(sessionKeyStorageKey())||"null");
            if(!await LockstepVault.restoreSessionKey(ownerSubject(),snapshot)){clearUnlockedSession();return false;}
        }catch{clearUnlockedSession();return false;}
    }
    state.lastActivityAt=lastActivity;
    return true;
}
function clearUnlockedSession(){
    if(state.token||state.subject){sessionStorage.removeItem(lockTimestampKey());sessionStorage.removeItem(sessionKeyStorageKey());}
}
function stopScreenLockWatch(){if(state.screenLockController){state.screenLockController.abort();state.screenLockController=null;}state.screenState=null;}
async function syncScreenLockWatch(){
    stopScreenLockWatch();
    if(!state.lockConfig.enabled||!state.lockConfig.lockOnScreenLock||!state.subject||!("IdleDetector" in window))return;
    const controller=new AbortController();state.screenLockController=controller;
    try{
        const detector=new IdleDetector();
        const lockForScreen=()=>{state.screenState=detector.screenState;if(detector.screenState==="locked"&&state.lockConfig.lockOnScreenLock&&LockstepVault.isUnlocked(state.subject))lockApp();};
        detector.addEventListener("change",lockForScreen);
        await detector.start({threshold:60000,signal:controller.signal});
        lockForScreen();
    }catch(error){if(error.name!=="AbortError")state.screenLockController=null;}
}
function enforceCurrentScreenLock(){if(state.lockConfig.enabled&&state.lockConfig.lockOnScreenLock&&state.screenState==="locked"&&state.subject&&LockstepVault.isUnlocked(state.subject))lockApp();}
function enforceScreenLockHeartbeat(){
    const now=Date.now();
    const delayed=state.screenLockHeartbeatVisible&&!document.hidden&&now-state.screenLockHeartbeatAt>DEVICE_LOCK_CHECK_MILLIS+DEVICE_SUSPEND_GRACE_MILLIS;
    state.screenLockHeartbeatAt=now;state.screenLockHeartbeatVisible=!document.hidden;
    enforceCurrentScreenLock();
    if(delayed&&state.lockConfig.enabled&&state.lockConfig.lockOnScreenLock&&state.subject&&LockstepVault.isUnlocked(state.subject))lockApp();
}
function updateLockSummary(){const duration=LOCK_TIMEOUT_LABELS.get(state.lockConfig.timeoutSeconds)||"inactivity";el("lock-summary").textContent=state.lockConfig.enabled?`Locks after ${duration}${state.lockConfig.lockOnScreenLock?" or when the screen locks":""}`:"Protect codes with a passkey";void syncScreenLockWatch();}
function recordPointerActivity(){const now=Date.now();if(now-state.lastPointerActivityAt<1000)return;state.lastPointerActivityAt=now;recordUserActivity();}
function recordUserActivity(){if((!state.token&&!state.subject)||el("signed-in").classList.contains("hidden"))return;state.lastActivityAt=Date.now();sessionStorage.setItem(lockTimestampKey(),String(state.lastActivityAt));persistUnlockedSession();scheduleInactivityLock();}
function scheduleInactivityLock(){stopInactivityWatch();if(!state.lockConfig.enabled)return;const remaining=Math.max(0,state.lockConfig.timeoutSeconds*1000-(Date.now()-state.lastActivityAt));state.inactivityTimer=setTimeout(enforceInactivityLock,remaining);}
function stopInactivityWatch(){if(state.inactivityTimer!==null){clearTimeout(state.inactivityTimer);state.inactivityTimer=null;}}
function enforceInactivityLock(){if((!state.token&&!state.subject)||!state.lockConfig.enabled||!el("locked").classList.contains("hidden"))return;const stored=Number(sessionStorage.getItem(lockTimestampKey())||state.lastActivityAt||0);if(Date.now()-stored>=state.lockConfig.timeoutSeconds*1000)lockApp();else{state.lastActivityAt=stored;scheduleInactivityLock();}}
function lockApp(){
    if(!state.token&&!state.subject)return;
    cancelVaultOperations(false);
    LockstepVault.lock(ownerSubject());
    clearUnlockedSession();
    closeVaultSurfaces();
    showLocked();
    schedulePendingSync(0);
}
async function unlockApp(event){
    event.preventDefault();hideInlineError("unlock-error");
    try{
        const owner=ownerSubject(),passcode=el("unlock-passcode").value;
        let serverConfig=null;
        try{serverConfig=await api("/api/v1/lock");await LockstepVault.synchronizeWrappedKey(owner,serverConfig.wrappedKey);}
        catch(error){if(error.code==="SESSION_EXPIRED")throw error;}
        if(!serverConfig){
            try{serverConfig=JSON.parse(localStorage.getItem(`authsync.lock.${owner}`));}catch{/* handled below */}
        }
        if(!serverConfig)throw new Error("Backend is currently unavailable. This vault must be unlocked online once before offline access is available.");
        await LockstepVault.unlock(owner,passcode);
        state.lockConfig=normalizeLockConfig({...serverConfig,enabled:true});
        if(serverConfig.wrappedKey){
            const localWrapped=await LockstepVault.exportWrappedKey(owner);
            const remoteAt=Number(serverConfig.wrappedKey.wrappedAt||serverConfig.wrappedKey.createdAt||0);
            if(localWrapped&&Number(localWrapped.wrappedAt||localWrapped.createdAt||0)>remoteAt){
                state.lockConfig=await api("/api/v1/lock",{method:"PUT",body:JSON.stringify({passcode,timeoutSeconds:state.lockConfig.timeoutSeconds||300,lockOnScreenLock:Boolean(state.lockConfig.lockOnScreenLock),wrappedKey:localWrapped})}).catch(()=>state.lockConfig);
            }
        }
        localStorage.setItem(`authsync.lock.${owner}`,JSON.stringify(state.lockConfig));
        el("unlock-passcode").value="";state.lastActivityAt=Date.now();sessionStorage.setItem(lockTimestampKey(),String(state.lastActivityAt));persistUnlockedSession();
        await showUnlockedApp();toast("Vault unlocked");
    }catch(error){if(error.code==="KEY_MISSING")signOut(false,"Local vault data was cleared. Sign in with Google again.");else if(error.code==="SESSION_EXPIRED")signOut(false,error.message);else showInlineError("unlock-error",error.message);}
}
async function openLockSettings({required=false,refresh=true}={}){try{if(refresh)state.lockConfig=normalizeLockConfig(await api("/api/v1/lock"));state.lockSetupRequired=required;updateLockSummary();el("lock-form").reset();el("lock-timeout").value=String(state.lockConfig.timeoutSeconds||300);el("lock-on-screen-lock").checked=Boolean(state.lockConfig.lockOnScreenLock);el("lock-dialog-title").textContent=required?"Create lock protection":"Change lock protection";el("lock-dialog-description").textContent=required?"Create a synchronized passkey before adding or viewing authenticator accounts. It cannot be recovered.":"Choose a new passkey and when Lockstep should lock.";el("lock-dialog-close").classList.toggle("hidden",required);hideInlineError("lock-error");el("settings-dialog").close();el("lock-dialog").showModal();el("lock-passcode").focus();}catch(error){if(!isVaultLockedError(error))toast(error.message,true);}}
async function saveLockSettings(event){
    event.preventDefault();hideInlineError("lock-error");
    const lockOnScreenLock=el("lock-on-screen-lock").checked;
    if(lockOnScreenLock){
        if(!("IdleDetector" in window)){showInlineError("lock-error","Screen-lock detection is not supported by this browser.");return;}
        try{if(await IdleDetector.requestPermission()!=="granted"){showInlineError("lock-error","Allow screen-lock detection to enable this option.");return;}}
        catch{showInlineError("lock-error","Screen-lock detection could not be enabled in this browser.");return;}
    }
    let epoch=null;try{if(state.lockConfig.enabled)epoch=beginVaultOperation();}catch{return;}
    const passcode=el("lock-passcode").value;
    if(passcode.length<4){showInlineError("lock-error","Passkey must contain at least 4 characters.");return;}
    if(passcode!==el("lock-confirm").value){showInlineError("lock-error","Passkeys do not match.");return;}
    try{
        await LockstepVault.configurePassphrase(ownerSubject(),passcode);if(epoch!==null)assertVaultOperation(epoch);
        const wrappedKey=await LockstepVault.exportWrappedKey(ownerSubject());if(epoch!==null)assertVaultOperation(epoch);
        state.lockConfig=normalizeLockConfig(await api("/api/v1/lock",{method:"PUT",body:JSON.stringify({passcode,timeoutSeconds:Number(el("lock-timeout").value),lockOnScreenLock,wrappedKey})}));
        if(epoch!==null)assertVaultOperation(epoch);state.lastActivityAt=Date.now();sessionStorage.setItem(lockTimestampKey(),String(state.lastActivityAt));persistUnlockedSession();
        el("lock-passcode").value="";el("lock-confirm").value="";state.lockSetupRequired=false;updateLockSummary();el("lock-dialog").close();el("lock-now").classList.remove("hidden");toast("Lock protection saved");scheduleInactivityLock();await loadEntries(true);
    }catch(error){if(!isVaultLockedError(error))showInlineError("lock-error",error.message);}
}

function confirmAction({title,message,label="Continue",iconName="shield",danger=false,passkey=false}) {
    const dialog=el("confirm-dialog"); el("confirm-title").textContent=title; el("confirm-message").textContent=message; el("confirm-accept").textContent=label;
    el("confirm-icon-use").setAttribute("href",`#i-${iconName}`); dialog.classList.toggle("danger",danger); dialog.returnValue="cancel";
    const input=el("confirm-passkey"); input.value=""; input.classList.toggle("hidden",!passkey); state.confirmPasskey="";
    dialog.showModal(); if(passkey) input.focus();
    return new Promise((resolve)=>{state.confirmationResolve=resolve;});
}
function resolveConfirmation(){const passkeyInput=el("confirm-passkey");state.confirmPasskey=passkeyInput.value;passkeyInput.value="";state.confirmationResolve?.(el("confirm-dialog").returnValue==="confirm");state.confirmationResolve=null;}

function cycleTheme(){const next=state.theme==="light"?"dark":"light";applyTheme(next);localStorage.setItem("authsync.theme",next);toast(`${next[0].toUpperCase()+next.slice(1)} theme`);}
function applyTheme(theme){state.theme=THEMES.includes(theme)?theme:"light";document.documentElement.dataset.theme=state.theme;el("theme-toggle")?.setAttribute("title",`Switch to ${state.theme==="dark"?"light":"dark"} theme`);document.querySelector('meta[name="theme-color"]')?.setAttribute("content",state.theme==="dark"?"#10131a":"#f7f8fb");}
function renderGoogleButton(){
    if(!window.google?.accounts?.id)return;
    const container=el("google-sign-in");
    if(container.dataset.gsiReady)return;
    container.dataset.gsiReady="1";
    container.replaceChildren();
    const gsiDiv=document.createElement("div");
    gsiDiv.id="gsi-btn-root";
    container.appendChild(gsiDiv);
    const compact = window.matchMedia("(max-width: 420px)").matches;
    google.accounts.id.renderButton(gsiDiv,{type:compact?"icon":"standard",ux_mode:"popup",callback:onGoogleCredential,theme:"outline",size:"large",text:"signin_with",shape:"pill",logo_alignment:"left"});
}
// The toast is a manual popover so it lives in the browser's top layer and is never hidden behind
// an open/closing <dialog> (settings, confirm, lock). Falls back to plain visibility if unsupported.
function hideToastNode(node){
    node.classList.remove("visible");
    clearTimeout(state.toastHideTimer);
    state.toastHideTimer=setTimeout(()=>{try{if(node.matches(":popover-open"))node.hidePopover();}catch{}},220);
}
function clearToast(){const node=el("toast");clearTimeout(state.toastTimer);node.textContent="";node.classList.remove("error");hideToastNode(node);}
// sticky=true keeps a progress message up until the next toast/clearToast (use for long-running work).
function toast(message,isError=false,sticky=false){
    const node=el("toast");
    clearTimeout(state.toastTimer);clearTimeout(state.toastHideTimer);
    node.textContent=message;node.classList.toggle("error",isError);
    try{if(node.matches(":popover-open"))node.hidePopover();node.showPopover();}catch{}
    void node.offsetWidth;
    node.classList.add("visible");
    if(!isError&&!sticky)state.toastTimer=setTimeout(()=>hideToastNode(node),4500);
}
function showInlineError(id,message){el(id).textContent=message;el(id).classList.remove("hidden");}
function hideInlineError(id){el(id).textContent="";el(id).classList.add("hidden");}
function formatCode(code){return code.length===6?`${code.slice(0,3)} ${code.slice(3)}`:code;}
function escapeHtml(value){const node=document.createElement("span");node.textContent=value;return node.innerHTML;}
function escapeAttribute(value){return String(value).replaceAll("&","&amp;").replaceAll('"',"&quot;").replaceAll("'","&#39;").replaceAll("<","&lt;").replaceAll(">","&gt;");}
function tokenClaims(token){try{return JSON.parse(atob(token.split(".")[1].replace(/-/g,"+").replace(/_/g,"/")));}catch{return null;}}
function isExpired(token){const claims=tokenClaims(token);return !claims||claims.exp*1000<Date.now()+30000;}

initialize().catch((error)=>{hideLoader();toast(error.message,true);});
