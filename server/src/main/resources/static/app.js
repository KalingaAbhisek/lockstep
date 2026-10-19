const el = (id) => document.getElementById(id);
const icon = (name) => `<svg aria-hidden="true"><use href="#i-${name}"></use></svg>`;
const EXPIRING_THRESHOLD_MILLIS = 5_000;
const THEMES = ["light", "dark"];
const state = {
    token: sessionStorage.getItem("authsync.idToken"), entries: [], serverOffsetMillis: 0,
    subject: localStorage.getItem("authsync.lastSubject"),
    refreshing: false, editing: false, originals: new Map(), pinnedIds: new Set(), entryOrder: [], dragId: null,
    theme: localStorage.getItem("authsync.theme") || "light", confirmationResolve: null, toastTimer: null, toastHideTimer: null, confirmPasskey: "",
    lockConfig: { enabled: false, timeoutSeconds: 60 }, inactivityTimer: null, lastActivityAt: Date.now(), lastPointerActivityAt: 0,
    offline: false, pendingChanges: 0, lockSetupRequired: false, lastSyncError: null,
    restoreAuthorized: sessionStorage.getItem("authsync.restoreAuthorized") === "1", restoreReturnView: "signed-out",
    displayName: localStorage.getItem("authsync.displayName") || ""
};
const cameraScanner = { stream:null, frameRequest:0, lastScanAt:0, frameCount:0, processing:false, lastValue:"", ignoreUntil:0 };

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
    if (state.token) {
        const claims = tokenClaims(state.token);
        state.displayName = claims?.name || claims?.given_name || claims?.email || state.displayName;
        if (state.displayName) localStorage.setItem("authsync.displayName", state.displayName);
    }
    if ("serviceWorker" in navigator) navigator.serviceWorker.register("/sw.js");
    bindEvents();
    if (!isSecureGoogleOrigin()) {
        hideLoader();
        toast(`Google Sign-In requires HTTPS for ${location.hostname}. Current origin: ${location.origin}`, true); return;
    }
    let config = null;
    try {
        config = await fetch("/api/v1/config", { cache: "no-store" }).then(response => response.json());
        if (config.googleClientId) localStorage.setItem("authsync.googleClientId", config.googleClientId);
    } catch { config = { googleClientId: localStorage.getItem("authsync.googleClientId") }; }
    if (config?.googleClientId && navigator.onLine) {
        try {
            await waitForGoogle();
            google.accounts.id.initialize({ client_id: config.googleClientId, callback: onGoogleCredential, auto_select: false });
            renderGoogleButton();
        } catch (error) { if (!state.token && !state.subject) throw error; }
    }
    if (state.token || state.subject) await showApp(false);
    else {
        signOut(false);
        if (!config?.googleClientId) toast("Connect once to configure Google Sign-In.", true);
    }
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
    el("camera-dialog").addEventListener("close", stopCameraScanner);
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
    ["pointerdown","keydown","touchstart","scroll"].forEach((eventName)=>document.addEventListener(eventName,recordUserActivity,{passive:true}));
    document.addEventListener("pointermove",recordPointerActivity,{passive:true});
    document.addEventListener("visibilitychange",()=>{
        if(document.hidden){stopInactivityWatch();if(el("camera-dialog").open)el("camera-dialog").close();}
        else{enforceInactivityLock();if((state.token||state.subject)&&!el("signed-in").classList.contains("hidden"))loadEntries();}
    });
    window.addEventListener("online", () => {
        if (!state.token && !state.subject) return;
        if (!el("signed-in").classList.contains("hidden")) loadEntries(true);
        else syncVault().catch(() => null);
    });
    window.addEventListener("focus",enforceInactivityLock);window.addEventListener("pageshow",enforceInactivityLock);document.addEventListener("resume",enforceInactivityLock);
    setInterval(enforceInactivityLock,15000);
}

function isSecureGoogleOrigin() {
    return location.protocol === "https:" || ["localhost", "127.0.0.1", "[::1]"].includes(location.hostname);
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
    const claims = tokenClaims(credential);
    state.token = credential;
    state.subject = claims?.sub;
    state.displayName = claims?.name || claims?.given_name || claims?.email || "";
    sessionStorage.setItem("authsync.idToken", credential);
    localStorage.setItem("authsync.lastSubject", state.subject);
    localStorage.setItem("authsync.displayName", state.displayName);
    clearToast();
    try { await showApp(true); }
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
            state.lockConfig = { enabled:false, timeoutSeconds:60 };
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
                await syncVault().catch(() => null);
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
        try { state.lockConfig = JSON.parse(localStorage.getItem(`authsync.lock.${ownerSubject()}`)) || { enabled:false, timeoutSeconds:60 }; }
        catch { state.lockConfig = { enabled:false, timeoutSeconds:60 }; }
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
        toast("Sign in again to create your app lock.", true);
        return;
    }
    await showUnlockedApp(false);
    await openLockSettings({ required: true, refresh: false });
}

async function showUnlockedApp(loadVault = true) {
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
        state.lockConfig = await api("/api/v1/lock", { method:"PUT", body:JSON.stringify({ passcode, timeoutSeconds:60, wrappedKey }) });
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
        signOut(false, "Vault reset. Sign in again to create a new app lock.");
    } catch (error) { showInlineError("restore-error", error.message); }
}

function signOut(showMessage = false, message = "Signed out securely") {
    stopInactivityWatch();
    if (el("settings-dialog").open) el("settings-dialog").close();
    if (state.subject) LockstepVault.lock(state.subject);
    const unlockKey = state.token || state.subject ? lockTimestampKey() : null;
    const sessionKey = state.token || state.subject ? sessionKeyStorageKey() : null;
    state.token = null;
    state.subject = null;
    state.entries = [];
    state.editing = false;
    sessionStorage.removeItem("authsync.idToken");
    sessionStorage.removeItem("authsync.restoreAuthorized");
    state.restoreAuthorized = false;
    localStorage.removeItem("authsync.lastSubject");
    localStorage.removeItem("authsync.displayName");
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
    const response = await fetch(path, {
        ...options, cache: "no-store",
        headers: { "Content-Type": "application/json", Authorization: `Bearer ${state.token}`, ...options.headers }
    });
    if (response.status === 401) {
        const error = new Error("Session expired. Sign in with Google again.");
        error.code = "SESSION_EXPIRED";
        throw error;
    }
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        throw new Error(body.error || `Request failed (${response.status})`);
    }
    return response;
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

function vaultTransport() {
    return {
        list: () => api("/api/v1/entries"),
        put: (id, payload) => api(`/api/v1/entries/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
        delete: (id) => api(`/api/v1/entries/${id}`, { method: "DELETE" })
    };
}

async function syncVault() {
    const owner = ownerSubject();
    const account = await api("/api/v1/account");
    if (!account.exists) {
        await LockstepVault.clearSubject(owner);
        localStorage.removeItem(`authsync.lock.${owner}`);
        const error = new Error("Your server account no longer exists. Sign in again to start fresh.");
        error.code = "ACCOUNT_MISSING";
        throw error;
    }
    return LockstepVault.synchronize(owner, vaultTransport());
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
    state.refreshing = true;
    const hasSkeleton = el("entries").querySelector(".entry-skel") !== null;
    const isEmpty = el("entries").innerHTML.trim() === "";
    if (hasSkeleton || isEmpty) renderEntrySkeleton();
    try {
        try { await syncVault(); state.offline = false; state.lastSyncError = null; }
        catch (error) {
            if (error.code === "SESSION_EXPIRED" || error.code === "ACCOUNT_MISSING") {
                signOut(false, error.message);
                return;
            }
            state.offline = true;
            state.lastSyncError = error.message;
        }
        state.pendingChanges = await LockstepVault.pendingCount(ownerSubject());
        const loaded = await LockstepVault.listEntries(ownerSubject());
        state.entries = loaded.map((entry) => ({ ...entry, pinned: state.pinnedIds.has(entry.id) }));
        sortLocalPins();
        state.serverOffsetMillis = 0;
        renderEntries();
        if (state.offline) el("account-summary").textContent += ` · Sync failed: ${state.lastSyncError || "Offline"}${state.pendingChanges ? ` · ${state.pendingChanges} change${state.pendingChanges === 1 ? "" : "s"} pending` : ""}`;
    } catch (error) {
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
    state.editing = value;
    if (value) state.originals = new Map(state.entries.map((entry) => [entry.id, { ...entry }]));
    el("view-tools").classList.toggle("hidden", value);
    el("edit-tools").classList.toggle("hidden", !value);
    renderEntries();
}

async function saveEdits() {
    syncDraftsFromInputs();
    if (state.entries.some((entry) => !entry.issuer.trim() || !entry.accountName.trim())) { toast("Issuer and account name are required", true); return; }
    el("save-edits").disabled = true;
    try {
        for (const entry of state.entries) {
            const original = state.originals.get(entry.id);
            if (!original || original.issuer !== entry.issuer.trim() || original.accountName !== entry.accountName.trim()) {
                await LockstepVault.updateEntry(ownerSubject(), entry.id, entry.issuer.trim(), entry.accountName.trim());
            }
        }
        saveLocalOrder();
        await syncVault().catch(() => null);
        state.editing = false;
        el("view-tools").classList.remove("hidden");
        el("edit-tools").classList.add("hidden");
        await loadEntries(true);
        toast("Changes saved");
    } catch (error) { toast(error.message, true); }
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
    const confirmed = await confirmAction({ title:"Remove account?", message:`${entry.issuer} (${entry.accountName}) will be removed from every synchronized device.`, label:"Remove", iconName:"trash", danger:true });
    if (!confirmed) return;
    try {
        await LockstepVault.deleteEntry(ownerSubject(), entry.id);
        await syncVault().catch(() => null);
        state.pinnedIds.delete(entry.id); saveLocalPins();
        state.entries = state.entries.filter((item) => item.id !== entry.id);
        saveLocalOrder();
        renderEntries(); toast("Account removed");
    } catch (error) { toast(error.message, true); }
}

function openAdd() { hideInlineError("add-error"); el("add-dialog").showModal(); }
function closeAdd() { hideInlineError("add-error"); el("add-dialog").close(); }
function openSubDialog(id) { el("add-dialog").close(); el(id).showModal(); }

async function addOtpUri(otpAuthUri) {
    await LockstepVault.addOtpUri(ownerSubject(), otpAuthUri);
    await syncVault().catch(() => null);
}

async function addManualEntry(event) {
    event.preventDefault(); hideInlineError("manual-error");
    const issuer=el("manual-issuer").value.trim(), account=el("manual-account").value.trim()||nextDefaultAccountName(state.entries);
    const secret=el("manual-secret").value.toUpperCase().replace(/[\s-]/g,"");
    if(!/^[A-Z2-7]+=*$/.test(secret)){showInlineError("manual-error","Secret must contain valid Base32 characters (A-Z and 2-7).");return;}
    const period=Number(el("manual-period").value);
    const query=new URLSearchParams({secret,issuer,algorithm:el("manual-algorithm").value,digits:el("manual-digits").value,period:String(period)});
    const uri=`otpauth://totp/${encodeURIComponent(`${issuer}:${account}`)}?${query}`;
    try{await addOtpUri(uri);el("manual-form").reset();el("manual-period").value="30";el("manual-dialog").close();await loadEntries(true);toast("Authenticator added");}
    catch(error){showInlineError("manual-error",error.message);}
}

async function importOtpUrls(event) {
    event.preventDefault(); hideInlineError("uri-error");
    try{const uris=parseBackup(el("otp-uris").value);const result=await importUris(uris);el("uri-form").reset();el("uri-dialog").close();await loadEntries(true);toast(result.failed?`${result.imported} imported; ${result.failed} failed`:`${result.imported} account${result.imported===1?"":"s"} imported`,result.failed>0);}
    catch(error){showInlineError("uri-error",error.message);}
}
async function openCameraScanner() {
    closeAdd();
    const dialog=el("camera-dialog");
    hideInlineError("camera-error");
    el("retry-camera").classList.add("hidden");
    el("camera-status").textContent="Point the camera at a TOTP QR code.";
    el("camera-starting").classList.remove("hidden");
    dialog.showModal();
    await startCameraStream();
}

async function startCameraStream() {
    stopCameraScanner();
    hideInlineError("camera-error");
    el("retry-camera").classList.add("hidden");
    el("camera-starting").textContent="Starting camera…";
    el("camera-starting").classList.remove("hidden");
    if (typeof window.jsQR !== "function") {
        showCameraError("The QR scanner could not be loaded. Refresh the page or import a saved QR image.");
        return;
    }
    if (!navigator.mediaDevices?.getUserMedia) {
        showCameraError("Live camera scanning is not supported in this browser. Import a saved QR image instead.");
        return;
    }
    try {
        cameraScanner.stream=await navigator.mediaDevices.getUserMedia({audio:false,video:{facingMode:{ideal:"environment"},width:{ideal:1280},height:{ideal:720}}});
        if (!el("camera-dialog").open) { stopCameraScanner(); return; }
        const video=el("camera-video");
        video.srcObject=cameraScanner.stream;
        await video.play();
        cameraScanner.lastScanAt=0;cameraScanner.frameCount=0;cameraScanner.lastValue="";cameraScanner.ignoreUntil=0;
        el("camera-starting").classList.add("hidden");
        recordUserActivity();
        cameraScanner.frameRequest=requestAnimationFrame(scanCameraFrame);
    } catch (error) {
        const denied=error?.name==="NotAllowedError"||error?.name==="SecurityError";
        const missing=error?.name==="NotFoundError"||error?.name==="OverconstrainedError";
        showCameraError(denied?"Camera access was blocked. Allow camera permission and try again.":missing?"No usable camera was found on this device.":"The camera could not be started. Try again or import a saved QR image.");
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
    cameraScanner.stream?.getTracks().forEach(track=>track.stop());
    cameraScanner.stream=null;cameraScanner.processing=false;
    const video=el("camera-video");
    if(video){video.pause();video.srcObject=null;}
}

function scanCameraFrame(timestamp) {
    cameraScanner.frameRequest=requestAnimationFrame(scanCameraFrame);
    if(cameraScanner.processing||timestamp-cameraScanner.lastScanAt<240||Date.now()<cameraScanner.ignoreUntil)return;
    const video=el("camera-video");
    if(!cameraScanner.stream||video.readyState<2||!video.videoWidth||!video.videoHeight)return;
    cameraScanner.lastScanAt=timestamp;cameraScanner.frameCount++;
    try {
        const canvas=el("camera-canvas"),maxDimension=720,scale=Math.min(1,maxDimension/Math.max(video.videoWidth,video.videoHeight));
        const width=Math.max(1,Math.round(video.videoWidth*scale)),height=Math.max(1,Math.round(video.videoHeight*scale));
        if(canvas.width!==width)canvas.width=width;if(canvas.height!==height)canvas.height=height;
        const context=canvas.getContext("2d",{willReadFrequently:true});
        context.drawImage(video,0,0,canvas.width,canvas.height);
        const pixels=context.getImageData(0,0,canvas.width,canvas.height);
        const decoded=window.jsQR?.(pixels.data,pixels.width,pixels.height,{inversionAttempts:cameraScanner.frameCount%5===0?"attemptBoth":"dontInvert"});
        if(decoded?.data)handleCameraResult(decoded.data);
    } catch {
        cameraScanner.ignoreUntil=Date.now()+500;
    }
}

async function handleCameraResult(value) {
    if(value===cameraScanner.lastValue&&Date.now()<cameraScanner.ignoreUntil)return;
    cameraScanner.lastValue=value;
    if(!value.startsWith("otpauth://totp/")){
        el("camera-status").textContent="That QR code is not a TOTP authenticator code.";
        cameraScanner.ignoreUntil=Date.now()+1400;
        return;
    }
    cameraScanner.processing=true;cameraScanner.ignoreUntil=Number.POSITIVE_INFINITY;
    el("camera-status").textContent="QR code found. Adding account…";
    recordUserActivity();
    try {
        await addOtpUri(value);
        el("camera-dialog").close();
        await loadEntries(true);
        toast("Authenticator added");
    } catch(error) {
        showInlineError("camera-error",error.message);
        el("camera-status").textContent="Point the camera at a TOTP QR code.";
        cameraScanner.processing=false;cameraScanner.ignoreUntil=Date.now()+1800;
    }
}

async function scanQrImage(event) {
    const files = [...event.target.files]; if (!files.length) return;
    try {
        toast(`Scanning ${files.length===1?"image":`${files.length} images`}…`,false,true);
        const uris=[];
        for(const file of files){let loaded;try{loaded=await loadQrImage(file);const uri=detectTotpQr(loaded.source);if(uri)uris.push(uri);}catch{/* reported as unreadable */}finally{loaded?.close();}await new Promise(requestAnimationFrame);}
        if (!uris.length) throw new Error("No TOTP QR code was found in the selected images.");
        const result=await importUris(uris),unreadable=files.length-uris.length;
        closeAdd();await loadEntries(true);toast(`${result.imported} imported${unreadable?`; ${unreadable} image${unreadable===1?"":"s"} unreadable`:""}`,unreadable>0||result.failed>0);
    } catch (error) { clearToast();showInlineError("add-error", error.message); }
    finally { event.target.value = ""; }
}

async function importUris(uris){let imported=0,failed=0;for(const otpAuthUri of uris){try{await addOtpUri(otpAuthUri);imported++;}catch{failed++;}}return{imported,failed};}
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
    el("qr-title").textContent = entry.issuer; el("qr-account").textContent = entry.accountName;
    el("qr-loading").textContent = ""; el("qr-loading").classList.add("hidden"); el("qr-skeleton").classList.remove("hidden"); el("qr-image").classList.add("hidden"); el("qr-dialog").showModal();
    try {
        const uri = await LockstepVault.otpAuthUri(ownerSubject(), entry.id);
        if (!globalThis.QRCode?.toDataURL) throw new Error("The local QR generator is unavailable.");
        el("qr-image").src = await globalThis.QRCode.toDataURL(uri, { errorCorrectionLevel: "M", margin: 2, width: 320 });
        el("qr-skeleton").classList.add("hidden"); el("qr-image").classList.remove("hidden"); el("qr-loading").classList.add("hidden");
    } catch (error) { el("qr-skeleton").classList.add("hidden"); el("qr-loading").textContent = error.message; el("qr-loading").classList.remove("hidden"); }
}
function clearQrDialog() { const source=el("qr-image").src; if(source.startsWith("blob:")) URL.revokeObjectURL(source); el("qr-skeleton").classList.remove("hidden"); el("qr-loading").classList.add("hidden"); el("qr-image").removeAttribute("src"); }

async function exportBackup() {
    const confirmed = await confirmAction({ title:"Export authenticator backup?", message:"The text file contains the secrets needed to generate every code. Store it somewhere private and never share it.", label:"Export backup", iconName:"export" });
    if (!confirmed) return;
    try {
        const text=await LockstepVault.exportText(ownerSubject()), url=URL.createObjectURL(new Blob([text], { type:"text/plain;charset=utf-8" })), link=document.createElement("a");
        link.href=url; link.download=`lockstep-totp-backup-${new Date().toISOString().slice(0,10)}.txt`; link.click(); setTimeout(()=>URL.revokeObjectURL(url),1000); toast("Backup exported");
    } catch(error) { toast(error.message,true); }
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
    try {
        const config = await api("/api/v1/lock");
        if (await LockstepVault.synchronizeWrappedKey(ownerSubject(), config.wrappedKey)) {
            state.lockConfig = config;
            lockApp();
            toast("The synchronized passkey changed. Unlock again before downloading the recovery key.", true);
            return;
        }
        downloadRecoveryKeyFile(await LockstepVault.exportRecoveryKey(ownerSubject()));
        toast("Recovery key downloaded. Store it somewhere private.");
    } catch (error) { toast(error.message, true); }
}

async function rotateEncryptionKey() {
    const settingsWasOpen = el("settings-dialog").open;
    if (settingsWasOpen) el("settings-dialog").close();
    const confirmed = await confirmAction({ title:"Rotate encryption key?", message:"A brand-new master key is generated and every account is re-encrypted with it. A NEW recovery key will be downloaded; your old recovery key stops working. Other devices pick up the new key the next time they unlock. Enter your passkey to continue.", label:"Rotate key", iconName:"lock", passkey:true });
    const passkey = state.confirmPasskey; state.confirmPasskey = "";
    if (!confirmed) { if (settingsWasOpen) openSettings(); return; }
    if (passkey.length < 4) { toast("Enter your passkey to rotate the encryption key.", true); if (settingsWasOpen) openSettings(); return; }
    toast("Rotating encryption key and synchronizing accounts…", false, true);
    let result = null;
    try {
        const owner = ownerSubject();
        await syncVault(); // must be online and fully synced before the key changes
        const remaining = await LockstepVault.pendingCount(owner);
        if (remaining > 0) throw new Error(`Cannot rotate while ${remaining} change${remaining === 1 ? " is" : "s are"} pending synchronization.`);
        result = await LockstepVault.rotateMasterKey(owner, passkey);
        downloadRecoveryKeyFile(result.recoveryKey); // save the new key before any network call can fail
        // Publish the new wrapped key BEFORE the re-encrypted entries so other devices can always decrypt what they pull.
        state.lockConfig = await api("/api/v1/lock", { method:"PUT", body:JSON.stringify({ passcode:passkey, timeoutSeconds:state.lockConfig.timeoutSeconds || 60, wrappedKey:result.wrappedKey }) });
        localStorage.setItem(`authsync.lock.${owner}`, JSON.stringify(state.lockConfig));
        await syncVault();
        await loadEntries(true);
        toast(`Key rotated to version ${result.version}. New recovery key downloaded; store it somewhere private.`);
    } catch (error) {
        if (result) toast(`Key rotated on this device (version ${result.version}) and the new recovery key was downloaded, but syncing failed: ${error.message} Unlock again to retry.`, true);
        else toast(error.message, true);
    }
}
async function importBackup(event) {
    const file=event.target.files?.[0]; event.target.value=""; if(!file)return;
    try {
        const uris=parseBackup(await file.text()); toast(`Importing ${uris.length} account${uris.length===1?"":"s"}…`);const {imported,failed}=await importUris(uris);
        await loadEntries(true); toast(failed?`${imported} imported; ${failed} failed`:`${imported} account${imported===1?"":"s"} imported`,failed>0);
    } catch(error){toast(error.message,true);}
}
function parseBackup(text) {
    const uris=text.split(/\r?\n/).map((line)=>line.trim()).filter((line)=>line&&!line.startsWith("#"));
    if(!uris.length)throw new Error("This backup does not contain any TOTP entries."); if(uris.length>500)throw new Error("A backup can contain at most 500 entries.");
    const invalid=uris.findIndex((line)=>!line.startsWith("otpauth://totp/")); if(invalid>=0)throw new Error(`Invalid TOTP URI on backup entry ${invalid+1}.`); return uris;
}
function nextDefaultAccountName(items){const highest=items.reduce((maximum,item)=>{const match=/^Account (\d+)$/.exec(item.accountName||"");return match?Math.max(maximum,Number(match[1])):maximum;},0);return `Account ${highest+1}`;}

function lockTimestampKey(){return `authsync.unlocked.${ownerSubject()}`;}
function sessionKeyStorageKey(){return `authsync.session-key.${ownerSubject()}`;}
function normalizeLockConfig(config){return{...(config||{}),enabled:Boolean(config?.enabled),timeoutSeconds:Number(config?.timeoutSeconds)>0?Number(config.timeoutSeconds):60};}
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
function updateLockSummary(){const labels={60:"Locks after 1 minute of inactivity",300:"Locks after 5 minutes of inactivity",900:"Locks after 15 minutes of inactivity",1800:"Locks after 30 minutes of inactivity"};el("lock-summary").textContent=state.lockConfig.enabled?(labels[state.lockConfig.timeoutSeconds]||"Locks after inactivity"):"Protect codes with a passkey";}
function recordPointerActivity(){const now=Date.now();if(now-state.lastPointerActivityAt<1000)return;state.lastPointerActivityAt=now;recordUserActivity();}
function recordUserActivity(){if((!state.token&&!state.subject)||el("signed-in").classList.contains("hidden"))return;state.lastActivityAt=Date.now();sessionStorage.setItem(lockTimestampKey(),String(state.lastActivityAt));persistUnlockedSession();scheduleInactivityLock();}
function scheduleInactivityLock(){stopInactivityWatch();if(!state.lockConfig.enabled)return;const remaining=Math.max(0,state.lockConfig.timeoutSeconds*1000-(Date.now()-state.lastActivityAt));state.inactivityTimer=setTimeout(enforceInactivityLock,remaining);}
function stopInactivityWatch(){if(state.inactivityTimer!==null){clearTimeout(state.inactivityTimer);state.inactivityTimer=null;}}
function enforceInactivityLock(){if((!state.token&&!state.subject)||!state.lockConfig.enabled)return;const stored=Number(sessionStorage.getItem(lockTimestampKey())||state.lastActivityAt||0);if(Date.now()-stored>=state.lockConfig.timeoutSeconds*1000)lockApp();else{state.lastActivityAt=stored;scheduleInactivityLock();}}
function lockApp(){LockstepVault.lock(ownerSubject());clearUnlockedSession();showLocked();}
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
        if(!serverConfig)throw new Error("Connect once before unlocking this vault offline.");
        await LockstepVault.unlock(owner,passcode);
        state.lockConfig=normalizeLockConfig({...serverConfig,enabled:true});
        if(serverConfig.wrappedKey){
            const localWrapped=await LockstepVault.exportWrappedKey(owner);
            const remoteAt=Number(serverConfig.wrappedKey.wrappedAt||serverConfig.wrappedKey.createdAt||0);
            if(localWrapped&&Number(localWrapped.wrappedAt||localWrapped.createdAt||0)>remoteAt){
                state.lockConfig=await api("/api/v1/lock",{method:"PUT",body:JSON.stringify({passcode,timeoutSeconds:state.lockConfig.timeoutSeconds||60,wrappedKey:localWrapped})}).catch(()=>state.lockConfig);
            }
        }
        localStorage.setItem(`authsync.lock.${owner}`,JSON.stringify(state.lockConfig));
        el("unlock-passcode").value="";state.lastActivityAt=Date.now();sessionStorage.setItem(lockTimestampKey(),String(state.lastActivityAt));persistUnlockedSession();
        await showUnlockedApp();toast("Vault unlocked");
    }catch(error){if(error.code==="KEY_MISSING")signOut(false,"Local vault data was cleared. Sign in with Google again.");else if(error.code==="SESSION_EXPIRED")signOut(false,error.message);else showInlineError("unlock-error",error.message);}
}
async function openLockSettings({required=false,refresh=true}={}){try{if(refresh)state.lockConfig=normalizeLockConfig(await api("/api/v1/lock"));state.lockSetupRequired=required;updateLockSummary();el("lock-form").reset();el("lock-timeout").value=String(state.lockConfig.timeoutSeconds||60);el("lock-dialog-title").textContent=required?"Create your app lock":"Change your app lock";el("lock-dialog-description").textContent=required?"Create a synchronized passkey before adding or viewing authenticator accounts. It cannot be recovered.":"Choose a new passkey for your web app and extension.";el("lock-dialog-close").classList.toggle("hidden",required);hideInlineError("lock-error");el("settings-dialog").close();el("lock-dialog").showModal();el("lock-passcode").focus();}catch(error){toast(error.message,true);}}
async function saveLockSettings(event){event.preventDefault();hideInlineError("lock-error");const passcode=el("lock-passcode").value;if(passcode.length<4){showInlineError("lock-error","Passkey must contain at least 4 characters.");return;}if(passcode!==el("lock-confirm").value){showInlineError("lock-error","Passkeys do not match.");return;}try{await LockstepVault.configurePassphrase(ownerSubject(),passcode);const wrappedKey=await LockstepVault.exportWrappedKey(ownerSubject());state.lockConfig=await api("/api/v1/lock",{method:"PUT",body:JSON.stringify({passcode,timeoutSeconds:Number(el("lock-timeout").value),wrappedKey})});state.lastActivityAt=Date.now();sessionStorage.setItem(lockTimestampKey(),String(state.lastActivityAt));persistUnlockedSession();el("lock-passcode").value="";el("lock-confirm").value="";state.lockSetupRequired=false;updateLockSummary();el("lock-dialog").close();el("lock-now").classList.remove("hidden");toast("Vault passkey synchronized");scheduleInactivityLock();await loadEntries(true);}catch(error){showInlineError("lock-error",error.message);}}

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
