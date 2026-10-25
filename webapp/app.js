const el = (id) => document.getElementById(id);
const API_BASE_URL = String(globalThis.LOCKSTEP_CONFIG?.apiBaseUrl || location.origin).trim().replace(/\/+$/, "");
const apiUrl = (path) => `${API_BASE_URL}${path.startsWith("/") ? path : `/${path}`}`;
const APP_BASE_URL = new URL(document.baseURI);
// When the API is reached through this site's own origin (a same-origin proxy such as /lockstep/api), the
// 30-day session lives in an HttpOnly cookie that page scripts cannot read. localStorage then only keeps
// this marker and the expiry time. With a separate API origin the session token is stored as before.
const COOKIE_SESSION = "cookie";
const USE_SESSION_COOKIE = (() => { try { return new URL(API_BASE_URL, location.href).origin === location.origin; } catch { return false; } })();
const EXPIRING_THRESHOLD_MILLIS = 5_000;
const reducedMotionPreference = matchMedia("(prefers-reduced-motion: reduce)");
const DEVICE_LOCK_CHECK_MILLIS = 30_000;
const DEVICE_SUSPEND_GRACE_MILLIS = 10_000;
const SESSION_REVOKED_NOTICE_KEY = "authsync.sessionRevokedNotice";
// Server checks happen on startup, when the tab is shown or focused, and when the connection returns.
// This interval is only a fallback for a tab that stays open and focused.
const BACKGROUND_REFRESH_MILLIS = 30_000;
const RETURN_REFRESH_GAP_MILLIS = 5_000;
// "system" follows the device's light/dark setting; the other two are explicit choices.
const THEMES = ["system", "light", "dark"];
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
    theme: localStorage.getItem("authsync.theme") || "system", confirmationResolve: null, toastTimer: null, toastHideTimer: null, confirmPasskey: "",
    lockConfig: { enabled: false, timeoutSeconds: 300, lockOnScreenLock: false }, inactivityTimer: null, lastActivityAt: Date.now(), lastPointerActivityAt: 0, screenLockController: null,
    screenState: null, screenLockHeartbeatAt: Date.now(), screenLockHeartbeatVisible: !document.hidden,
    offline: false, pendingChanges: 0, lockSetupRequired: false, lastSyncError: null,
    restoreAuthorized: sessionStorage.getItem("authsync.restoreAuthorized") === "1", restoreReturnView: "signed-out",
    displayName: localStorage.getItem("authsync.displayName") || "",
    vaultEpoch: 0, vaultRequests: new AbortController(), tokenExpiryTimer: null,
    pendingSyncTimer: null, pendingSyncRunning: false, pendingSyncRequested: false,
    bootstrapUnsupported: false, batchUnsupported: false, changesUnsupported: false, prefetchedVault: null,
    revealOnRender: false, localRefreshing: false, lastReturnRefreshAt: 0, googleClientId: ""
};
const cameraScanner = { stream:null, source:"camera", frameRequest:0, frameTimer:null, lastScanAt:0, frameCount:0, processing:false, lastValue:"", ignoreUntil:0, selection:null, selectionDrag:null };

// ---- Passphrase helpers: strength estimate and a random suggestion -------------------------------------
// New or changed passphrases need at least 12 characters. A suggestion is six random words from a
// 256-word list plus a number (about 55 bits of randomness), generated locally with crypto.getRandomValues.
const NEW_PASSPHRASE_MIN_LENGTH = 12;
const PASSPHRASE_WORDS = "acorn actor adobe agent album alpha amber anchor angle apple apron arena armor arrow aspen atlas attic audio autumn avenue badge bagel baker bamboo banjo barley basil basin beach beacon berry bison blade blanket bloom bonus border brave breeze brick bridge bright broom brush bucket buffalo bundle cabin cactus camel candle canoe canyon carbon cargo carpet castle cedar cellar cement chalk charm cherry chess chorus cider cinema citrus clever cliff clock cloud clover coast cobalt cocoa comet coral cotton cousin crane crater crayon cricket crystal cuckoo daisy dancer dawn delta denim desert diamond dinner dolphin donkey dragon dream drift drum eagle earth easel echo eclipse elbow elder ember engine falcon fancy feather fence fiber fiddle field finch flame flute forest fossil fountain fox frost galaxy garden garlic gecko giant ginger glacier globe glove goose granite grape gravel guitar hammer harbor hazel helmet herald hollow honey horizon hotel humble iceberg igloo island ivory jacket jaguar jasmine jelly jewel jungle kayak kernel kettle kiwi koala ladder lagoon lantern laptop lemon lilac linen lizard lobster locket lotus lunar magnet mango maple marble meadow melody mesa meteor mimic mint mirror mitten modem monsoon mosaic moss motor muffin nectar needle nickel noble nutmeg oasis ocean olive onion opal orbit orchid otter oyster paddle palace panda paper parrot pastel peach pebble pencil pepper piano pickle pigeon pillow pilot pine planet plaza plum polar pony poppy potato prairie prism pumpkin puzzle quartz quiet quill rabbit radar radish raven reef ribbon river robin rocket saddle saffron salmon sandal satin scarf shadow shell signal silver".split(" ");
function passphraseStrength(value) {
    if (!value) return { level: "", label: "" };
    let pool = 0;
    if (/[a-z]/.test(value)) pool += 26;
    if (/[A-Z]/.test(value)) pool += 26;
    if (/[0-9]/.test(value)) pool += 10;
    if (/[^A-Za-z0-9]/.test(value)) pool += 33;
    const bits = Math.min(value.length, new Set(value).size * 2) * Math.log2(Math.max(pool, 2));
    if (value.length < NEW_PASSPHRASE_MIN_LENGTH) return { level: "weak", label: `Too short: use at least ${NEW_PASSPHRASE_MIN_LENGTH} characters` };
    if (bits < 60) return { level: "weak", label: "Weak: add more words or characters" };
    if (bits < 80) return { level: "fair", label: "Fair" };
    return { level: "strong", label: "Strong" };
}
function suggestPassphrase() {
    const random = crypto.getRandomValues(new Uint16Array(7));
    const words = Array.from(random.slice(0, 6), (value) => PASSPHRASE_WORDS[value % PASSPHRASE_WORDS.length]);
    return `${words.join("-")}-${random[6] % 100}`;
}
// Wires a strength label and a "Suggest a passphrase" button to a new-passphrase field and its confirmation.
function bindPassphraseHelpers(form, input, confirm, strength, suggest, suggestion) {
    const update = () => { const result = passphraseStrength(input.value); strength.textContent = result.label; strength.dataset.level = result.level; };
    input.addEventListener("input", update);
    suggest.addEventListener("click", () => {
        const value = suggestPassphrase();
        input.value = value; confirm.value = value; update();
        suggestion.textContent = `Suggested passphrase (write it down somewhere safe): ${value}`;
        suggestion.classList.remove("hidden");
    });
    form.addEventListener("reset", () => { strength.textContent = ""; strength.dataset.level = ""; suggestion.textContent = ""; suggestion.classList.add("hidden"); });
}

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
        actions.classList.remove("actions-pending");
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
    applyTheme(THEMES.includes(state.theme) ? state.theme : "system");
    matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", () => { if (state.theme === "system") applyTheme("system"); });
    renderConnectivityStatus(navigator.onLine);
    if(state.token&&!state.subject){state.token=null;sessionStorage.removeItem("authsync.idToken");}
    if(state.subject&&appSessionHasExpired())signOut(false,"Your 30-day Lockstep session has expired. Sign in with Google again.");
    if (state.token) {
        const claims = tokenClaims(state.token);
        state.displayName = claims?.name || claims?.given_name || claims?.email || state.displayName;
        if (state.displayName) localStorage.setItem("authsync.displayName", state.displayName);
        scheduleGoogleSessionExpiry();
    }
    if ("serviceWorker" in navigator) navigator.serviceWorker.register(trustedScriptUrl(new URL("sw.js", APP_BASE_URL).href));
    bindEvents();
    if (!isSecureGoogleOrigin()) {
        hideLoader();
        toast(`Google Sign-In requires HTTPS for ${location.hostname}. Current origin: ${location.origin}`, true); return;
    }
    const config = await loadPublicConfig();
    state.googleClientId = config?.googleClientId || "";
    // Google's script is only needed for the sign-in button, so a signed-in user never downloads it.
    if (!state.token && !state.subject) await ensureGoogleSignIn().catch(() => null);
    if (state.token && navigator.onLine) await ensureAppSession().catch(() => null);
    state.revealOnRender = true;
    if (state.token || state.subject) await showApp(false);
    else {
        signOut(false);
        if (!config?.googleClientId) toast("Can't reach Lockstep. Check your internet connection and try again.", true);
    }
    schedulePendingSync(0);
    checkConnectivity();
    if (el("signed-in").classList.contains("hidden")) void checkActiveSession();
    state.lastReturnRefreshAt = Date.now();
    showStoredSessionRevokedNotice();
    revealApp();
    scheduleVendorPreload();
}

// Hides the startup loader once. Called as soon as saved codes are on screen, or when startup finishes.
function revealApp() {
    if (!state.revealOnRender) return;
    state.revealOnRender = false;
    hideLoader();
}

// The Google client ID comes from config.js when the deployment sets it (no request at all). Otherwise a
// saved copy is used and refreshed in the background at most once a day; only a first visit waits for it.
const CONFIG_REFRESH_MILLIS = 24 * 60 * 60 * 1000;
async function loadPublicConfig() {
    const configured = String(globalThis.LOCKSTEP_CONFIG?.googleClientId || "").trim();
    if (configured && !configured.includes("${")) {
        try { localStorage.setItem("authsync.googleClientId", configured); } catch { /* storage unavailable */ }
        return { googleClientId: configured };
    }
    const saved = localStorage.getItem("authsync.googleClientId");
    const checkedAt = Number(localStorage.getItem("authsync.googleClientIdCheckedAt") || 0);
    const refresh = () => fetch(apiUrl("/api/v1/config"), { cache: "no-store" })
        .then(response => response.json())
        .then(config => {
            if (config?.googleClientId) {
                localStorage.setItem("authsync.googleClientId", config.googleClientId);
                localStorage.setItem("authsync.googleClientIdCheckedAt", String(Date.now()));
            }
            return config;
        });
    if (saved) {
        if (Date.now() - checkedAt > CONFIG_REFRESH_MILLIS) refresh().catch(() => null);
        return { googleClientId: saved };
    }
    try { return await refresh(); }
    catch { return { googleClientId: localStorage.getItem("authsync.googleClientId") }; }
}

// QR libraries (about 280 KB) are only needed for scanning or showing a QR code, so they are not part
// of startup. They load in the background once the app is on screen, or on demand if used sooner.
const VENDOR_SCRIPTS = { jsQR: "vendor/jsQR.js", QRCode: "vendor/qrcode.js", LockstepArgon2id: "vendor/argon2id.js" };
// Argon2id (vault key protection) is loaded only when a vault needs it.
globalThis.LockstepLoadArgon2id = () => loadVendorScript("LockstepArgon2id");
const vendorLoads = new Map();
// Trusted Types: the only script URLs this page loads are its service worker, its own vendor files and
// Google's sign-in script.
const scriptUrlPolicy = globalThis.trustedTypes?.createPolicy?.("lockstep-scripts", {
    createScriptURL(url) {
        const allowed = new Set([...["sw.js", ...Object.values(VENDOR_SCRIPTS)].map((path) => new URL(path, APP_BASE_URL).href), GOOGLE_SIGN_IN_SCRIPT]);
        if (!allowed.has(url)) throw new TypeError(`Script URL not allowed: ${url}`);
        return url;
    }
});
const trustedScriptUrl = (url) => scriptUrlPolicy ? scriptUrlPolicy.createScriptURL(url) : url;
function loadVendorScript(name) {
    if (globalThis[name]) return Promise.resolve();
    if (vendorLoads.has(name)) return vendorLoads.get(name);
    const pending = new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = trustedScriptUrl(new URL(VENDOR_SCRIPTS[name], APP_BASE_URL).href);
        script.async = true;
        script.onload = () => resolve();
        script.onerror = () => { vendorLoads.delete(name); script.remove(); reject(new Error(`${name} could not be loaded.`)); };
        document.head.append(script);
    });
    vendorLoads.set(name, pending);
    return pending;
}
function scheduleVendorPreload() {
    const preload = () => { loadVendorScript("jsQR").catch(() => null); loadVendorScript("QRCode").catch(() => null); };
    if (typeof requestIdleCallback === "function") requestIdleCallback(preload, { timeout: 3000 });
    else setTimeout(preload, 1000);
}

function bindEvents() {
    el("theme-toggle").addEventListener("click", cycleTheme);
    el("sign-out").addEventListener("click", userSignOut);
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
    el("settings-signout").addEventListener("click", () => { el("settings-dialog").close(); userSignOut(); });
    el("settings-signout-all").addEventListener("click", signOutEverywhere);
    el("reauth-dialog").addEventListener("close", cancelRecentGoogleSignIn);
    el("settings-lock").addEventListener("click", openLockSettings);
    el("lock-form").addEventListener("submit", saveLockSettings);
    bindPassphraseHelpers(el("lock-form"), el("lock-passcode"), el("lock-confirm"), el("lock-strength"), el("lock-suggest"), el("lock-suggestion"));
    bindPassphraseHelpers(el("restore-form"), el("restore-passcode"), el("restore-passcode-confirm"), el("restore-strength"), el("restore-suggest"), el("restore-suggestion"));
    el("lock-dialog").addEventListener("cancel", event => { if (state.lockSetupRequired) event.preventDefault(); });
    el("lock-now").addEventListener("click", () => { lockApp(); toast("Vault locked"); });
    el("unlock-form").addEventListener("submit", unlockApp);
    el("forgot-passkey").addEventListener("click", () => showRestore("locked"));
    el("restore-form").addEventListener("submit", restoreVault);
    el("restore-key-file").addEventListener("change", loadRecoveryKeyFile);
    el("restore-reset").addEventListener("click", resetVault);
    el("restore-signout").addEventListener("click", userSignOut);
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
    // Passphrases, secrets, otpauth URLs and suggested passphrases never stay in a closed form.
    [["manual-dialog","manual-form"],["uri-dialog","uri-form"],["lock-dialog","lock-form"]].forEach(([dialog,form])=>el(dialog).addEventListener("close",()=>{el(form).reset();if(form==="manual-form")el("manual-period").value="30";hideInlineError(form.replace("-form","-error"));}));
    el("toast").addEventListener("click", clearToast);
    // Dialog "close" events do not bubble; a capturing listener sees every one, after the dialog's own handlers.
    document.addEventListener("close", () => setTimeout(flushLiveRedraw, 0), true);
    // Enter in the passphrase field confirms, like submitting a form.
    el("confirm-passkey").addEventListener("keydown", (event) => { if (event.key === "Enter" && !event.isComposing) { event.preventDefault(); el("confirm-dialog").close("confirm"); } });
    // The seconds label changes once a second and the progress bar is a CSS transition, so 4 checks a second
    // are enough to switch codes on time.
    setInterval(tick, 250);
    setInterval(checkConnectivity, 10000); // local only, no request
    setInterval(()=>refreshFromServer(true), BACKGROUND_REFRESH_MILLIS);
    setInterval(reconcileLiveChanges, 1000);
    setInterval(enforceScreenLockHeartbeat,DEVICE_LOCK_CHECK_MILLIS);
    ["pointerdown","keydown","touchstart","scroll"].forEach((eventName)=>document.addEventListener(eventName,recordUserActivity,{passive:true}));
    document.addEventListener("pointermove",recordPointerActivity,{passive:true});
    document.addEventListener("visibilitychange",()=>{
        state.screenLockHeartbeatAt=Date.now();state.screenLockHeartbeatVisible=!document.hidden;
        if(document.hidden){stopInactivityWatch();if(el("camera-dialog").open&&cameraScanner.source!=="screen")el("camera-dialog").close();}
        else{enforceCurrentScreenLock();enforceInactivityLock();refreshFromServer();}
    });
    window.addEventListener("online", () => {
        resetNetworkBackoff();
        stopPendingSyncRetry();
        checkConnectivity();
        void checkActiveSession();
        schedulePendingSync(0);
        if (isVaultOperational()) loadEntries(true);
    });
    window.addEventListener("storage", event => {
        if(state.subject && event.key===`authsync.erased.${state.subject}`){
            signOut(false,"Signed out in another tab. This browser's vault was removed.",true);
        }
    });
    // The summary under "Your codes" says why syncing stopped; refresh it with the device's state at once.
    window.addEventListener("offline",()=>{renderConnectivityStatus(false);stopPendingSyncRetry();if(!el("signed-in").classList.contains("hidden"))updateAccountSummary();});
    window.addEventListener("focus",enforceInactivityLock);window.addEventListener("focus",()=>refreshFromServer());window.addEventListener("pageshow",enforceInactivityLock);document.addEventListener("resume",enforceInactivityLock);
    setInterval(enforceInactivityLock,15000);
}

// One server check when the user comes back to the app. While the vault is open, the sync request itself
// validates the session; on the lock screen (or any other view) only the session is checked.
function refreshFromServer(fromTimer = false) {
    if (document.hidden || (!state.token && !state.subject)) return;
    if (state.editing || document.querySelector("dialog[open]:not(#settings-dialog)")) {
        void refreshLockWhileBusy();
        return;
    }
    const now = Date.now();
    if (!fromTimer && now - state.lastReturnRefreshAt < RETURN_REFRESH_GAP_MILLIS) return;
    state.lastReturnRefreshAt = now;
    if (!el("signed-in").classList.contains("hidden")) loadEntries();
    else void checkActiveSession();
}

let liveChanges = null, liveChangesIdentity = "";
const LIVE_SUPPORT_KEY = "authsync.liveChangesSupported";
// What the server said the last time this browser asked; refreshed by every successful startup request.
function rememberedLiveSupport() { try { return localStorage.getItem(LIVE_SUPPORT_KEY) === "1"; } catch { return false; } }
function liveShareHash(text) { // FNV-1a; only names a lock and a channel inside this browser
    let hash = 0x811c9dc5;
    for (let i = 0; i < text.length; i++) hash = Math.imul(hash ^ text.charCodeAt(i), 0x01000193);
    return (hash >>> 0).toString(36);
}
function reconcileLiveChanges() {
    if (state.endingSessionRequests) return;
    const authentication = authenticationSnapshot();
    const identity = (state.liveChangesSupported ?? rememberedLiveSupport()) && state.lockConfig.enabled && state.subject && appSessionToken() ? JSON.stringify(authentication) : "";
    if (identity === liveChangesIdentity) return;
    liveChanges?.stop(); liveChanges = null; liveChangesIdentity = identity;
    if (!identity) return;
    liveChanges = LockstepLiveChanges.watch({
        // The tabs signed in with this session share one connection (see live-changes.js); the name is a hash
        // of the sign-in, so tabs of an older and a newer sign-in never pass each other's events.
        shareKey: `lockstep-live-${liveShareHash(identity)}`,
        connect: signal => authenticatedFetch("/api/v1/events", {signal, expectedAuthentication:authentication, eventStream:true}),
        // The server says this session ended. Confirmed with one request before signing out: only an answer that
        // the session was replaced or expired signs out (api() routes that); if it is still valid, the live
        // connection reconnects; if the server cannot be reached, it is asked again shortly.
        onSession: () => confirmLiveSessionEnd(authentication),
        onChange: async () => {
            if (!authenticationMatches(authentication)) throw Object.assign(new Error("Sign-in changed"),{code:"SESSION_CHANGED"});
            if (state.refreshing) throw new Error("Sync in progress");
            const epoch = isVaultOperational() ? beginVaultOperation() : null;
            state.prefetchedVault = null;
            try { await syncVault(epoch, true); }
            catch (error) {
                if (error.code === "ACCOUNT_MISSING" && authenticationMatches(authentication)) { signOut(false,error.message); return; }
                if (error.code === "VAULT_LOCKED" && authenticationMatches(authentication)) {
                    await syncVault(null, true); // Keep the new ciphertext usable for a later offline unlock.
                    return;
                }
                throw error;
            }
            if (epoch === null) return;
            assertVaultOperation(epoch);
            if (!state.editing && !document.querySelector("dialog[open]:not(#settings-dialog)")) await loadEntries(true);
            else state.liveRedrawPending = true;
        }
    });
}
// A change from another device that arrived during edit mode or while a dialog was open is already stored
// here; the list is redrawn as soon as editing ends or the dialog closes, not at the next 30-second check.
function flushLiveRedraw() {
    if (!state.liveRedrawPending || state.refreshing || state.editing || document.querySelector("dialog[open]:not(#settings-dialog)") || !isVaultOperational()) return;
    void loadEntries(true);
}

async function refreshLockWhileBusy() {
    if (state.remoteLockChecking || !isVaultOperational()) return;
    state.remoteLockChecking = true;
    const epoch = state.vaultEpoch;
    const authentication = authenticationSnapshot();
    try {
        assertSyncCooldown(authentication.subject);
        const latest = await api("/api/v1/lock", { expectedAuthentication: authentication });
        assertVaultOperation(epoch);
        await applySynchronizedLock(authentication.subject, latest, authentication);
    } catch {
        // Offline and in-progress local rotations retry on the next refresh. Authentication failures
        // are routed by the API; a changed remote key is routed by applySynchronizedLock.
    } finally { state.remoteLockChecking = false; }
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

async function confirmLiveSessionEnd(authentication, attempt = 0) {
    const message = "This Lockstep session ended on another device. Sign in again.";
    // Another tab of this browser may have confirmed it first and removed the shared session: then this tab
    // signs out too. (A new sign-in made meanwhile in another tab is left alone.)
    const handledElsewhere = () => {
        if (authenticationMatches(authentication)) return false;
        if (state.subject === authentication.subject && !appSessionToken()) showSessionRevoked(message);
        return true;
    };
    if (handledElsewhere()) return;
    try {
        await api("/api/v1/session", { expectedAuthentication: authentication });
        if (authenticationMatches(authentication)) { liveChanges = null; liveChangesIdentity = ""; } // still valid: reconnect
    } catch (error) {
        if (handledElsewhere() || ["SESSION_REVOKED", "SESSION_EXPIRED"].includes(error?.code)) return; // routed by api()
        if (attempt < 3) setTimeout(() => void confirmLiveSessionEnd(authentication, attempt + 1), TRANSIENT_RETRY_MIN_MILLIS);
        else showSessionRevoked(message);
    }
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
    // Nobody sees a hidden tab, so skip the check there; it runs again as soon as the tab is shown.
    if(document.hidden)return;
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

// Loads Google's sign-in script on demand and renders the button once. Only the signed-out page needs it:
// the 30-day Lockstep session does not depend on Google's script.
const GOOGLE_SIGN_IN_SCRIPT = "https://accounts.google.com/gsi/client";
const GOOGLE_SIGN_IN_STYLES = "https://accounts.google.com/gsi/style";
let googleStylesReady = null;
function ensureGoogleStyles() {
    googleStylesReady ||= new Promise((resolve, reject) => {
        const link = document.createElement("link");
        link.rel = "stylesheet";
        link.href = GOOGLE_SIGN_IN_STYLES;
        const timer = setTimeout(() => fail(), 10000);
        function fail() {
            clearTimeout(timer);
            link.remove();
            googleStylesReady = null;
            reject(new Error("Google Sign-In styles could not be loaded. Check your connection and try again."));
        }
        link.onload = () => { clearTimeout(timer); resolve(); };
        link.onerror = fail;
        document.head.append(link);
    });
    return googleStylesReady;
}
let googleSignInReady = null;
function ensureGoogleSignIn() {
    const clientId = state.googleClientId || localStorage.getItem("authsync.googleClientId") || "";
    if (!clientId || !navigator.onLine) return Promise.resolve();
    googleSignInReady ||= (async () => {
        // Load Google's CSP-allowed external CSS explicitly. Its injected fallback can otherwise leave
        // both the visible label and screen-reader text exposed as an unstyled button.
        await ensureGoogleStyles();
        if (!window.google?.accounts?.id && !document.querySelector(`script[src="${GOOGLE_SIGN_IN_SCRIPT}"]`)) {
            const script = document.createElement("script");
            script.src = trustedScriptUrl(GOOGLE_SIGN_IN_SCRIPT);
            script.async = true;
            document.head.append(script);
        }
        await waitForGoogle();
        google.accounts.id.initialize({ client_id: clientId, callback: onGoogleCredential, auto_select: false });
        renderGoogleButton();
    })().catch((error) => {
        googleSignInReady = null;
        const container = el("google-sign-in");
        container.replaceChildren();
        delete container.dataset.gsiReady;
        const retry = document.createElement("button");
        retry.type = "button";
        retry.className = "round-button";
        retry.textContent = "Retry Google sign-in";
        retry.addEventListener("click", () => ensureGoogleSignIn().catch(error => toast(error.message, true)));
        container.append(retry);
        throw error;
    });
    return googleSignInReady;
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
    if (state.reauthResolve) { completeRecentGoogleSignIn(credential); return; }
    const claims=tokenClaims(credential);
    if(!claims?.sub){toast("Google sign-in could not be verified. Try again.",true);return;}
    const attempt=crypto.randomUUID();state.signInAttempt=attempt;
    showLoader();
    cancelVaultOperations();
    if(state.subject && state.subject!==claims.sub)clearUnlockedSession();
    closeVaultSurfaces();
    state.entries=[];el("entries").replaceChildren();el("unlock-passcode").value="";
    localStorage.removeItem(SESSION_REVOKED_NOTICE_KEY);
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
        if (error.code!=="SESSION_CHANGED") signOut(false,error.message||"Sign-in could not be completed. Try again.");
    }
    finally { if(state.signInAttempt===attempt)hideLoader(); }
}

// Resetting the vault, rotating the recovery key, replacing the passphrase and signing out of every device
// need a Google sign-in from the last few minutes (the server allows five), not only the 30-day session.
// When the current Google credential is older, a dialog asks the user to confirm with Google.
const RECENT_SIGN_IN_MILLIS = 4 * 60 * 1000;
function hasRecentGoogleSignIn() {
    const claims = state.token ? tokenClaims(state.token) : null;
    return Boolean(claims?.iat && !isExpired(state.token) && Date.now() - claims.iat * 1000 < RECENT_SIGN_IN_MILLIS);
}
async function ensureRecentGoogleSignIn(reason) {
    if (hasRecentGoogleSignIn()) return true;
    if (!navigator.onLine) { toast("Connect to the internet to confirm with Google.", true); return false; }
    return new Promise((resolve) => {
        state.reauthResolve = resolve;
        el("reauth-message").textContent = reason;
        hideInlineError("reauth-error");
        const target = el("reauth-google");
        target.replaceChildren();
        el("reauth-dialog").showModal();
        ensureGoogleSignIn().then(() => {
            if (state.reauthResolve !== resolve) return;
            google.accounts.id.renderButton(target, { type: "standard", theme: effectiveTheme() === "dark" ? "filled_black" : "outline",
                size: "large", text: "continue_with", shape: "pill", logo_alignment: "left" });
        }).catch(() => showInlineError("reauth-error", "Google Sign-In could not be loaded. Check your connection and try again."));
    });
}
function completeRecentGoogleSignIn(credential) {
    const claims = tokenClaims(credential);
    if (!claims?.sub || claims.sub !== state.subject) {
        showInlineError("reauth-error", "Continue with the Google account this vault belongs to.");
        return;
    }
    const resolve = state.reauthResolve;
    state.reauthResolve = null;
    state.token = credential;
    sessionStorage.setItem("authsync.idToken", credential);
    scheduleGoogleSessionExpiry();
    el("reauth-dialog").close();
    resolve(true);
}
function cancelRecentGoogleSignIn() {
    const resolve = state.reauthResolve;
    state.reauthResolve = null;
    if (!resolve) return;
    toast("Google confirmation was cancelled. Nothing was changed.", true);
    resolve(false);
}

// One request for everything startup needs (account status, lock settings and the encrypted vault).
// Falls back to the separate requests when the API has not been updated yet.
function assertStartupAuthentication(startup) {
    if (!startup?.authentication || !authenticationMatches(startup.authentication)) throw Object.assign(new Error("Your sign-in changed. Try again."), {code:"SESSION_CHANGED"});
}
async function fetchStartupState(owner) {
    const capturedGeneration = authenticationSnapshot().generation;
    const authentication = authenticationSnapshot();
    if (authentication.subject !== owner || capturedGeneration !== authentication.generation) throw Object.assign(new Error("Your sign-in changed. Try again."), {code:"SESSION_CHANGED"});
    const request = (path) => api(path, {expectedAuthentication:authentication});
    assertSyncCooldown(owner);

    const generation = LockstepVault.syncGeneration(owner);
    const localGeneration = await LockstepVault.localGeneration(owner);
    if (!state.bootstrapUnsupported) {
        try {
            // With a cursor saved by the last sync, only the changes since then are downloaded.
            const since = await LockstepVault.startupCursor(owner);
            const startup = await request(`/api/v1/bootstrap${since == null ? "" : `?since=${encodeURIComponent(since)}`}`);
            assertStartupAuthentication({authentication});
            LockstepVault.setLabelEncryption(Array.isArray(startup?.features) && startup.features.includes("encryptedLabels"));
            LockstepVault.setArgon2idWrapping(Array.isArray(startup?.features) && startup.features.includes("argon2idWrapping"));
            state.liveChangesSupported = Array.isArray(startup?.features) && startup.features.includes("liveChanges");
            // Remembered, so a startup request that fails for a moment does not leave this tab without live updates.
            try { localStorage.setItem(LIVE_SUPPORT_KEY, state.liveChangesSupported ? "1" : "0"); } catch { /* storage unavailable */ }
            return { authentication, exists: Boolean(startup?.exists), lock: startup?.lock, entries: Array.isArray(startup?.entries) ? startup.entries : null, cursor: startup?.cursor ?? null,
                full: since == null || startup?.full !== false, deletedIds: Array.isArray(startup?.deletedIds) ? startup.deletedIds : [], generation, localGeneration };
        } catch (error) {
            if (error.status !== 404 && error.status !== 405) throw error;
            state.bootstrapUnsupported = true;
            state.liveChangesSupported = false;
            try { localStorage.setItem(LIVE_SUPPORT_KEY, "0"); } catch { /* storage unavailable */ }
        }
    }
    const account = await request("/api/v1/account");
    const lock = await request("/api/v1/lock");
    return { authentication, exists: Boolean(account?.exists), lock, entries: null, cursor: null, generation };
}

// The first synchronization after startup reuses the vault list from the bootstrap response
// instead of asking the server for the account and the list a second time.
function takePrefetchedVault(owner) {
    const prefetched = state.prefetchedVault;
    state.prefetchedVault = null;
    if (!prefetched || prefetched.owner !== owner || Date.now() - prefetched.fetchedAt > 30000) return null;
    if(!prefetched.authentication || !authenticationMatches(prefetched.authentication)) return null;
    return prefetched;
}

async function showApp(afterLogin = false) {
    loadLocalPins();
    state.prefetchedVault = null;
    state.startupCheck = null;
    // The startup request starts at once; when this browser already holds the vault, its codes are shown
    // without waiting for it (see openFromDevice) and the answer is checked as soon as it arrives.
    const startupRequest = fetchStartupState(ownerSubject());
    startupRequest.catch(() => null);
    if (!afterLogin && await openFromDevice(ownerSubject(), startupRequest)) return;
    let startup = null;
    try {
        startup = await startupRequest;
        assertStartupAuthentication(startup);
        const account = { exists: startup.exists };
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
            const sharedConfig = startup.lock;
            if (startup.entries) state.prefetchedVault = { owner: ownerSubject(), authentication: startup.authentication, entries: startup.entries, cursor: startup.cursor, full: startup.full, deletedIds: startup.deletedIds, generation: startup.generation, localGeneration: startup.localGeneration, fetchedAt: Date.now() };
            await LockstepVault.synchronizeWrappedKey(ownerSubject(), sharedConfig.wrappedKey, sharedConfig.vaultRevision);
            assertStartupAuthentication(startup);
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
        if (error.code === "SESSION_CHANGED") return;
        if (error.code === "SESSION_EXPIRED" || error.code === "ACCOUNT_MISSING") {
            signOut(false);
            toast(error.message, true);
            return;
        }
    }
    let lockConfigLoadedFromServer = false;
    try {
        if (!startup?.lock) throw new Error("Lockstep could not load your lock settings. Try again.");
        state.lockConfig = startup.lock;
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

// Reopening the app: if this browser holds the protected vault and the last known lock settings, show the
// lock screen or (within the lock timeout) the saved codes immediately. The startup answer is then checked
// before the first sync uses it: a deleted account signs out, a passphrase or recovery key changed on
// another device locks the vault, and new lock settings are applied.
async function openFromDevice(owner, startupRequest) {
    let cached = null;
    try { cached = JSON.parse(localStorage.getItem(`authsync.lock.${owner}`) || "null"); } catch { /* use the normal path */ }
    if (!cached?.enabled || !appSessionToken() || await LockstepVault.keyState(owner) !== "wrapped") return false;
    state.lockConfig = normalizeLockConfig(cached);
    updateLockSummary();
    state.startupCheck = startupRequest.then((startup) => applyStartupState(owner, startup)).catch((error) => { scheduleStartupRetry(owner, error); return null; });
    if (!await resumeUnlockedSession()) { showLocked(); return true; }
    if (navigator.onLine) {
        // This tab may have been away (another site, a reopened tab) while the key, the passphrase or the
        // session changed elsewhere. Codes appear only after the startup check already running has answered
        // (it locks or signs out this tab if needed); a slow server delays them at most 1.5 s, and offline the
        // device's vault opens at once.
        await Promise.race([state.startupCheck, new Promise(resolve => setTimeout(resolve, 1500))]);
        if (ownerSubject() !== owner || !appSessionToken()) return true; // signed out meanwhile
        if (!LockstepVault.isUnlocked(owner)) { if (el("locked").classList.contains("hidden")) showLocked(); return true; }
    }
    await showUnlockedApp();
    return true;
}
// The startup check (lock settings, key, account) failed for a temporary reason while this browser's vault was
// opened: it runs again in 5 to 10 seconds (or when a retry delay ends), so a passphrase or key changed elsewhere
// still locks this tab promptly. Sign-in problems are routed by api() and never retried here.
function scheduleStartupRetry(owner, error) {
    const status = Number(error?.status || 0);
    if (!(error?.code === "SYNC_COOLDOWN" || !status || status === 408 || status === 429 || status >= 500)) return;
    clearTimeout(state.startupRetryTimer);
    const spacing = error?.code === "SYNC_COOLDOWN" ? 250 : TRANSIENT_RETRY_MIN_MILLIS + Math.random() * (TRANSIENT_RETRY_MAX_MILLIS - TRANSIENT_RETRY_MIN_MILLIS);
    state.startupRetryTimer = setTimeout(async () => {
        state.startupRetryTimer = null;
        if (ownerSubject() !== owner || !appSessionToken() || !navigator.onLine) return;
        try { await applyStartupState(owner, await fetchStartupState(owner)); }
        catch (next) { if (next?.code !== "SESSION_CHANGED") scheduleStartupRetry(owner, next); }
    }, Math.max(error?.retryAfterMillis || 0, retryDelay(owner), spacing));
}
async function applyStartupState(owner, startup) {
    assertStartupAuthentication(startup);
    if (ownerSubject() !== owner) return;
    if (!startup.exists) {
        await LockstepVault.clearSubject(owner);
        localStorage.removeItem(`authsync.lock.${owner}`);
        signOut(false);
        toast("Your server account no longer exists. Sign in again to start fresh.", true);
        return;
    }
    if (!startup.lock) return;
    if (startup.entries) state.prefetchedVault = { owner, authentication: startup.authentication, entries: startup.entries, cursor: startup.cursor, full: startup.full, deletedIds: startup.deletedIds, generation: startup.generation, localGeneration: startup.localGeneration, fetchedAt: Date.now() };
    const changed = await LockstepVault.synchronizeWrappedKey(owner, startup.lock.wrappedKey, startup.lock.vaultRevision);
    assertStartupAuthentication(startup);
    localStorage.setItem(`authsync.lock.${owner}`, JSON.stringify(startup.lock));
    state.lockConfig = normalizeLockConfig({ ...startup.lock, enabled: true });
    updateLockSummary();
    if (changed) {
        state.prefetchedVault = null;
        if (el("locked").classList.contains("hidden")) { lockApp(); toast("Your passphrase or recovery key changed on another device. Unlock again.", true); }
    } else if (LockstepVault.isUnlocked(owner)) scheduleInactivityLock();
}

async function showUnlockedApp(loadVault = true) {
    if(loadVault&&state.lockConfig.enabled&&state.subject&&!LockstepVault.isUnlocked(state.subject)){showLocked();return;}
    el("signed-out").classList.add("hidden");
    el("locked").classList.add("hidden");
    el("restore").classList.add("hidden");
    el("signed-in").classList.remove("hidden");
    clearRestoreForm();
    el("welcome-message").textContent = state.displayName ? `Welcome, ${state.displayName}` : "Welcome";
    animateIn(el("signed-in"));
    el("sign-out").classList.remove("hidden");
    el("google-sign-in").classList.add("hidden");
    el("open-settings").classList.remove("hidden");
    el("lock-now").classList.toggle("hidden", !state.lockConfig.enabled);
    recordUserActivity();
    if (loadVault) { renderEntrySkeleton(); await loadEntries(); }
}

// The recovery key and new passphrase never stay in the hidden restore form.
function clearRestoreForm() {
    state.recoveryFileRead=(state.recoveryFileRead||0)+1;
    el("restore-form").reset(); el("restore-key-file").value = ""; el("restore-file-name").textContent = ""; hideInlineError("restore-error");
}

function showLocked() {
    // A sync that discovers a replaced or expired session signs out first; it must not then show the
    // lock screen over the signed-out page and its notice.
    if (!state.token && !state.subject) return;
    clearRestoreForm();
    const entering = el("locked").classList.contains("hidden");
    stopInactivityWatch();
    state.entries=[]; el("entries").replaceChildren();
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

// Files are checked for size before they are read: a backup holds at most 500 accounts (well under 2 MiB, even
// encrypted), and a recovery-key file is a few hundred bytes.
const MAX_BACKUP_FILE_BYTES = 8 * 1024 * 1024;
const MAX_RECOVERY_KEY_FILE_BYTES = 16 * 1024;
async function loadRecoveryKeyFile(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    const epoch=state.vaultEpoch,owner=state.subject,read=state.recoveryFileRead=(state.recoveryFileRead||0)+1;
    const current=()=>epoch===state.vaultEpoch&&owner===state.subject&&read===state.recoveryFileRead&&!el("restore").classList.contains("hidden");
    try {
        if (file.size > MAX_RECOVERY_KEY_FILE_BYTES) throw new Error("This file is too large to be a Lockstep recovery key.");
        const match = (await file.text()).match(/LS2-M-[A-Za-z0-9_-]{43}/);
        if(!current())return;
        if (!match) throw new Error("The selected file does not contain a valid Lockstep recovery key.");
        el("restore-key").value = match[0];
        el("restore-file-name").textContent = file.name;
        hideInlineError("restore-error");
    } catch (error) {
        if(!current())return;
        if (error.code === "SESSION_CHANGED") return;
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
    if (passcode.length < NEW_PASSPHRASE_MIN_LENGTH) { showInlineError("restore-error", `Passphrase must contain at least ${NEW_PASSPHRASE_MIN_LENGTH} characters.`); return; }
    if (passcode !== el("restore-passcode-confirm").value) { showInlineError("restore-error", "Passphrases do not match."); return; }
    const owner=ownerSubject(),epoch=state.vaultEpoch,authentication=authenticationSnapshot();
    const check=()=>{if(state.vaultEpoch!==epoch || !authenticationMatches(authentication))throw vaultLockedError();};
    try {
        if ((await LockstepVault.expectedRevision(ownerSubject())) !== null && !await ensureRecentGoogleSignIn("Confirm with Google to restore your vault.")) return;
        await syncVault();
        check();
        const version = await LockstepVault.importRecoveryKey(owner, recoveryKey, passcode);
        check();
        const wrappedKey = await LockstepVault.exportWrappedKey(ownerSubject());
        const expectedRevision = await LockstepVault.expectedRevision(ownerSubject());
        state.lockConfig = await api("/api/v1/lock", { method:"PUT", body:JSON.stringify({ timeoutSeconds:300, lockOnScreenLock:false, wrappedKey, expectedRevision }) });
        check();
        await LockstepVault.markWrappedKeySynced(ownerSubject(), state.lockConfig?.vaultRevision,state.lockConfig?.wrappedKey);
        check();
        localStorage.setItem(`authsync.lock.${ownerSubject()}`, JSON.stringify(state.lockConfig));
        state.restoreAuthorized = false;
        sessionStorage.removeItem("authsync.restoreAuthorized");
        sessionStorage.setItem(lockTimestampKey(), String(Date.now()));
        clearRestoreForm();
        clearToast();
        await showUnlockedApp(true);
        toast(`Vault restored with recovery key version ${version}`);
    } catch (error) {
        if (isVaultLockedError(error)) return;
        if (error.code === "SESSION_EXPIRED" || error.code === "ACCOUNT_MISSING") signOut(false, error.message);
        else showInlineError("restore-error", error.message);
    }
}

async function resetVault() {
    const owner = ownerSubject();
    const confirmed = await confirmAction({ title:"Reset vault?", message:"Enter your Lockstep passphrase. This permanently deletes all authenticator accounts and vault data from this device and the server. This cannot be undone.", label:"Reset", iconName:"trash", danger:true, passphrase:true });
    const passphrase = state.confirmPasskey; state.confirmPasskey = "";
    if (!confirmed) return;
    try {
        if (!await LockstepVault.exportWrappedKey(owner)) throw new Error("Open this vault on this device before resetting it.");
        if (!await LockstepVault.checkPassphrase(owner, passphrase)) throw new Error("Incorrect passphrase. Nothing was deleted.");
        if (!await ensureRecentGoogleSignIn("Confirm with Google to reset your vault.")) return;
        if (owner !== ownerSubject()) return;
        await api("/api/v1/vault", { method:"DELETE" });
        await LockstepVault.clearSubject(owner);
        localStorage.removeItem(`authsync.lock.${owner}`);
        sessionStorage.removeItem(`authsync.unlocked.${owner}`);
        signOut(false, "Vault reset. Sign in again to create lock protection.");
    } catch (error) { showInlineError("restore-error", error.message); }
}

// Signing out also ends the session on the server, so a copied session token stops working at once.
// Best effort: the request is sent with keepalive and local sign-out never waits for it.
function userSignOut() { return signOutAndErase(); }

function finishUserSignOut() {
    try {
        const appSession = appSessionToken();
        if (state.subject && appSession && navigator.onLine) {
            const googleToken = state.token && !isExpired(state.token) ? state.token : "";
            fetch(apiUrl("/api/v1/session"), { method: "DELETE", keepalive: true, cache: "no-store",
                headers: { ...(googleToken ? { Authorization: `Bearer ${googleToken}` } : { "X-Lockstep-Subject": state.subject }),
                    "X-Lockstep-Client": "web", ...(appSession !== COOKIE_SESSION ? { "X-Lockstep-Session": appSession } : {}) } }).catch(() => null);
        }
    } catch { /* local sign-out below still happens */ }
    signOut(true);
}

// For shared or borrowed computers: also removes this browser's encrypted copy of the vault (accounts, vault
// key and queued changes). Signing in again downloads everything; changes not uploaded yet would be lost.
async function signOutAndErase() {
    if (el("settings-dialog").open) el("settings-dialog").close();
    const owner = state.subject;
    if (!owner) return;
    const authentication=authenticationSnapshot();
    const confirmed = await confirmAction({ title: "Sign out?", label: "Sign out", iconName: "trash", danger: true,
        message: "This browser's encrypted copy of your vault is deleted and you are signed out. Your synchronized accounts stay on the server and on your other devices. Any accounts or changes that have not uploaded will be permanently lost." });
    if (!confirmed || !authenticationMatches(authentication)) return;
    localStorage.setItem(`authsync.erased.${owner}`,crypto.randomUUID());
    lockApp();
    try {
        await LockstepVault.clearSubject(owner);
        for (const key of [`authsync.lock.${owner}`, `authsync.pins.${owner}`, `authsync.order.${owner}`]) localStorage.removeItem(key);
        if(authenticationMatches(authentication))finishUserSignOut();
        toast("Signed out. This browser's copy of the vault was removed.");
    } catch (error) {
        toast("Could not remove this browser's vault data. Please try signing out again.",true);
    }
}

// Ends every Lockstep session of this account (all browsers and the extension), then signs out here.
async function signOutEverywhere() {
    if (el("settings-dialog").open) el("settings-dialog").close();
    const confirmed = await confirmAction({ title:"Sign out of all devices?", message:"Every browser and extension signed in to your Lockstep account is signed out. Each one needs a Google sign-in again; your accounts stay saved.", label:"Sign out everywhere", iconName:"logout" });
    if (!confirmed) return;
    if (!await ensureRecentGoogleSignIn("Confirm with Google to sign out of all devices.")) return;
    const authentication=authenticationSnapshot();
    try {
        await api("/api/v1/session?all=true", { method:"DELETE" });
        if(authenticationMatches(authentication))signOut(false, "Signed out of all devices");
    } catch (error) {
        if (error.code === "SESSION_CHANGED") return;
        if (error.code === "SESSION_EXPIRED" || error.code === "SESSION_REVOKED") signOut(false, error.message);
        else toast(`Could not sign out of all devices: ${error.message}`, true);
    }
}

function signOut(showMessage = false, message = "Signed out securely", preserveSharedSession = false) {
    stopScreenLockWatch();
    stopInactivityWatch();
    stopPendingSyncRetry();
    // A retry delay belongs to the session that ended: the next sign-in syncs at once.
    syncRetryStates.clear(); clearTimeout(state.listRetryTimer); state.listRetryTimer = null;
    clearTimeout(state.startupRetryTimer); state.startupRetryTimer = null;
    cancelVaultOperations();
    closeVaultSurfaces();
    clearTimeout(state.tokenExpiryTimer);state.tokenExpiryTimer=null;
    if (el("settings-dialog").open) el("settings-dialog").close();
    if (state.subject) LockstepVault.lock(state.subject);
    const owner=state.subject||tokenClaims(state.token)?.sub||null;
    const unlockKey = state.token || state.subject ? lockTimestampKey() : null;
    const sessionKey = state.token || state.subject ? sessionKeyStorageKey() : null;
    if (owner) LockstepVault.forgetSessionKey(owner, sessionStorage.getItem(SESSION_TAB_KEY)).catch(() => null);
    state.token = null;
    state.subject = null;
    state.entries = [];
    el("entries").replaceChildren();
    state.editing = false;
    sessionStorage.removeItem("authsync.idToken");
    localStorage.removeItem("authsync.idToken");
    sessionStorage.removeItem("authsync.restoreAuthorized");
    state.restoreAuthorized = false;
    localStorage.removeItem("authsync.lastSubject");
    localStorage.removeItem("authsync.displayName");
    if(owner&&!preserveSharedSession){localStorage.removeItem(`authsync.appSession.web.${owner}`);localStorage.removeItem(`authsync.appSessionExpiry.web.${owner}`);localStorage.removeItem(`authsync.appSessionGeneration.web.${owner}`);}
    state.displayName = "";
    if (unlockKey) sessionStorage.removeItem(unlockKey);
    if (sessionKey) sessionStorage.removeItem(sessionKey);
    window.google?.accounts?.id?.disableAutoSelect();
    clearRestoreForm(); el("unlock-passcode").value = "";
    el("signed-out").classList.remove("hidden");
    if (showMessage) animateIn(el("signed-out"));
    el("signed-in").classList.add("hidden");
    el("locked").classList.add("hidden");
    el("restore").classList.add("hidden");
    el("sign-out").classList.add("hidden");
    el("google-sign-in").classList.remove("hidden");
    ensureGoogleSignIn().catch(() => null);
    el("open-settings").classList.add("hidden");
    el("lock-now").classList.add("hidden");
    if (showMessage || message !== "Signed out securely") toast(message, message !== "Signed out securely");
}

async function authenticatedFetch(path, options = {}) {
    const authentication = options.expectedAuthentication || authenticationSnapshot();
    if(!authenticationMatches(authentication))throw Object.assign(new Error("Your sign-in changed. Try again."),{code:"SESSION_CHANGED"});
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
        signal: AbortSignal.any([options.signal || state.vaultRequests.signal, AbortSignal.timeout(options.eventStream ? 270000 : 45000)]),
        headers: { "Content-Type":"application/json", ...(googleToken?{Authorization:`Bearer ${googleToken}`}:{"X-Lockstep-Subject":state.subject}), "X-Lockstep-Client":"web", ...(appSession&&appSession!==COOKIE_SESSION?{"X-Lockstep-Session":appSession}:{}), ...options.headers }
    });
    if (!authenticationMatches(authentication)) {
        const error=new Error("Your sign-in changed while this request was running. Try again.");error.code="SESSION_CHANGED";throw error;
    }
    if (!response.ok) {
        const body = await response.json().catch(() => ({}));
        const error = new Error(body.error || (response.status === 401 ? "Session expired. Sign in with Google again." : `Lockstep could not complete the request (error ${response.status}). Try again.`));
        error.code = body.code || (response.status === 401 ? "SESSION_EXPIRED" : "REQUEST_FAILED");
        error.status = response.status;error.retryAfterMillis=retryAfterMillis(response);
        if(error.code==="SESSION_REVOKED" || error.code==="SESSION_EXPIRED") {
            if (!authenticationMatches(authentication)) {
                error.code="SESSION_CHANGED";
                error.message="Your sign-in changed while this request was running. Try again.";
            } else if(error.code==="SESSION_REVOKED")showSessionRevoked(error.message);
            else signOut(false,error.message);
        }
        throw error;
    }
    return response;
}

function appSessionStorageKey(subject=ownerSubject()) { return `authsync.appSession.web.${subject}`; }
function appSessionExpiryStorageKey(subject=ownerSubject()) { return `authsync.appSessionExpiry.web.${subject}`; }
function authenticationSnapshot() {
    const subject=state.subject;
    return { subject, token:subject?localStorage.getItem(appSessionStorageKey(subject)):null,
        generation:subject?localStorage.getItem(`authsync.appSessionGeneration.web.${subject}`):null };
}
function authenticationMatches(snapshot) {
    const current=authenticationSnapshot();
    return current.subject===snapshot.subject && current.token===snapshot.token && current.generation===snapshot.generation;
}
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
    const subject=ownerSubject(),generation=crypto.randomUUID();
    localStorage.setItem(`authsync.appSessionGeneration.web.${subject}`,generation);
    if(!state.token)throw new Error("Sign in with Google first.");
    const response=await fetch(apiUrl("/api/v1/session"),{
        method:"POST",cache:"no-store",signal:AbortSignal.timeout(45000),
        headers:{"Content-Type":"application/json",Authorization:`Bearer ${state.token}`,"X-Lockstep-Client":"web",...(USE_SESSION_COOKIE?{"X-Lockstep-Session-Mode":"cookie"}:{})}
    });
    const body=await response.json().catch(()=>({}));
    // Cookie mode: the server keeps the token in an HttpOnly cookie and does not return it.
    if(response.ok&&!body.sessionToken&&USE_SESSION_COOKIE&&body.expiresAtEpochMillis)body.sessionToken=COOKIE_SESSION;
    if (state.subject!==subject || localStorage.getItem(`authsync.appSessionGeneration.web.${subject}`)!==generation) {
        const error=new Error("Your sign-in changed. Try again.");error.code="SESSION_CHANGED";throw error;
    }
    if(!response.ok||!body.sessionToken){
        const error=new Error(body.error||(response.status===401?"Session expired. Sign in with Google again.":`Lockstep could not complete the request (error ${response.status}). Try again.`));
        error.code=body.code||(response.status===401?"SESSION_EXPIRED":"REQUEST_FAILED");
        throw error;
    }
    localStorage.setItem(appSessionStorageKey(subject),body.sessionToken);
    if(body.expiresAtEpochMillis)localStorage.setItem(appSessionExpiryStorageKey(subject),String(body.expiresAtEpochMillis));
    return body.sessionToken;
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
    const owner = options.expectedAuthentication?.subject || state.subject;
    const endingSession = options.method === "DELETE" && (path === "/api/v1/vault" || path.startsWith("/api/v1/session"));
    if (endingSession) {
        state.endingSessionRequests = (state.endingSessionRequests || 0) + 1;
        liveChanges?.stop(); liveChanges = null; liveChangesIdentity = "";
    }
    try { return await apiRequest(path, options); }
    catch (error) {
        if (error?.name === "TimeoutError" || error?.name === "AbortError" && !options.signal?.aborted && !state.vaultRequests.signal.aborted) {
            error = Object.assign(new Error("Lockstep took too long to respond. Your change may still have reached the server; sync will retry safely."), {code:"BACKEND_UNAVAILABLE"});
        }
        if(error.code === "BACKEND_UNAVAILABLE" || error.status === 429 || error.status >= 500 || error instanceof TypeError) recordSyncFailure(owner,error);
        throw error;
    } finally { if (endingSession) state.endingSessionRequests--; }
}

async function apiRequest(path, options = {}) {
    const authentication=authenticationSnapshot();
    const response = await authenticatedFetch(path, options);
    const result=response.status===204?null:await response.json();
    if(!authenticationMatches(authentication)){const error=new Error("Your sign-in changed. Try again.");error.code="SESSION_CHANGED";throw error;}
    return result;
}

function ownerSubject() {
    const subject = tokenClaims(state.token)?.sub || state.subject;
    if (!subject) throw new Error("Sign in with Google first.");
    return subject;
}

function vaultLockedError() { const error=new Error("Vault locked. Unlock it to continue.");error.code="VAULT_LOCKED";return error; }
function isVaultLockedError(error) { return error?.code==="VAULT_LOCKED"||error?.name==="AbortError"&&!isVaultOperational(); }
function isVaultOperational() { return Boolean(state.subject&&LockstepVault.isUnlocked(state.subject)&&el("locked").classList.contains("hidden")&&!el("signed-in").classList.contains("hidden")); }
function beginVaultOperation() { enforceCurrentScreenLock();enforceInactivityLock();if(!isVaultOperational())throw vaultLockedError();return state.vaultEpoch; }
function assertVaultOperation(epoch) { if(epoch!==state.vaultEpoch||!isVaultOperational())throw vaultLockedError(); }
function cancelVaultOperations(abortRequests = true) { state.vaultEpoch++;if(abortRequests){state.vaultRequests.abort();state.vaultRequests=new AbortController();}state.refreshing=false;state.localRefreshing=false; }
function closeVaultSurfaces() {
    // A question still open (or answered a moment ago, before its close event arrived) counts as cancelled.
    if(state.confirmationResolve)state.confirmationAborted=true;
    stopCameraScanner();clearDragState();state.editing=false;
    ["manual-form","uri-form","lock-form"].forEach(id=>el(id)?.reset());el("confirm-passkey").value="";el("backup-password").value="";el("backup-password-confirm").value="";
    ["add-dialog","manual-dialog","uri-dialog","settings-dialog","qr-dialog","camera-dialog","confirm-dialog","lock-dialog","backup-dialog"].forEach(id=>{const dialog=el(id);if(dialog?.open)dialog.close("cancel");});
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

async function applySynchronizedLock(owner, latestLock, authentication) {
    const check=()=>{if(authentication.subject!==owner||!authenticationMatches(authentication))throw Object.assign(new Error("Your sign-in changed. Try again."),{code:"SESSION_CHANGED"});};
    check();
    if(!latestLock)throw new Error("The server did not return vault lock settings.");
    const wasUnlocked=LockstepVault.isUnlocked(owner);
    const changed=await LockstepVault.synchronizeWrappedKey(owner,latestLock.wrappedKey,latestLock.vaultRevision);
    const revision=await LockstepVault.expectedRevision(owner);
    check();
    if(Number.isInteger(latestLock.vaultRevision)&&Number.isInteger(revision)&&latestLock.vaultRevision<revision){
        if(wasUnlocked&&!LockstepVault.isUnlocked(owner)){lockApp();throw vaultLockedError();}
        throw Object.assign(new Error("A newer vault revision is already on this device. Sync again."),{code:"VAULT_CHANGED",status:409});
    }
    state.lockConfig=normalizeLockConfig(latestLock);
    localStorage.setItem(`authsync.lock.${owner}`,JSON.stringify(state.lockConfig));
    updateLockSummary();
    if(changed&&wasUnlocked){
        lockApp();
        toast("Your passphrase or recovery key changed on another device. Enter your current passphrase to continue.",true);
        throw vaultLockedError();
    }
    if(wasUnlocked){scheduleInactivityLock();enforceInactivityLock();}
}

function vaultTransport(owner) {
    const generation = authenticationSnapshot().generation;
    const captured = Promise.resolve(authenticationSnapshot());
    const boundApi = async (path, options = {}) => {
        assertSyncCooldown(owner);
        const authentication = await captured;
        if (authentication.subject !== owner || generation !== authentication.generation) throw Object.assign(new Error("Your sign-in changed. Try again."), {code:"SESSION_CHANGED"});
        return api(path, {...options, expectedAuthentication:authentication});
    };
    return {
        list: () => boundApi("/api/v1/entries"),
        put: (id, payload) => boundApi(`/api/v1/entries/${id}`, { method: "PUT", body: JSON.stringify(payload) }),
        delete: (id) => boundApi(`/api/v1/entries/${id}`, { method: "DELETE" }),
        // Entries changed or deleted since a cursor (full list when since is null); null on older servers.
        changes: async (since) => {
            if(!state.bootstrapUnsupported){
                try {
                    const snapshot=await boundApi(`/api/v1/bootstrap${since==null?"":`?since=${encodeURIComponent(since)}`}`);
                    if(!snapshot.exists)throw Object.assign(new Error("Your server account no longer exists. Sign in again to start fresh."),{code:"ACCOUNT_MISSING"});
                    await applySynchronizedLock(owner,snapshot.lock,await captured);
                    return snapshot;
                } catch(error) {
                    if(error.status!==404&&error.status!==405)throw error;
                    state.bootstrapUnsupported=true;
                }
            }
            if (state.changesUnsupported) return null;
            try { return await boundApi(`/api/v1/entries/changes${since == null ? "" : `?since=${encodeURIComponent(since)}`}`); }
            catch (error) {
                if (error.status !== 404 && error.status !== 405) throw error;
                state.changesUnsupported = true;
                return null;
            }
        },
        batch: async (operations) => {
            if (state.batchUnsupported) return null;
            try { return await boundApi("/api/v1/entries/batch", { method: "POST", body: JSON.stringify({ operations }) }); }
            catch (error) {
                if (error.status !== 404 && error.status !== 405) throw error;
                state.batchUnsupported = true;
                return null;
            }
        }
    };
}

// A change the server refused for good (and that was dropped) is reported instead of a success message for
// the action that caused it, whichever upload (the background retry or the action's own sync) noticed it.
function rememberDropNotice(message){state.dropNotice={message,at:Date.now()};}
function successToast(message,since){const notice=state.dropNotice;if(notice&&notice.at>=since){toast(notice.message,true);return;}toast(message);}

async function flushPendingVault(owner = state.subject) {
    if(!owner||!appSessionToken())return null;
    try{return await LockstepVault.flushOutbox(owner,vaultTransport(owner));}
    catch(error){
        if(error.code==="SESSION_EXPIRED")signOut(false,error.message);
        else if(error.dropped||error.code==="STALE_KEY"||error.code==="VAULT_RESET"){rememberDropNotice(error.message);toast(error.message,true);schedulePendingSync(0);} // that change was dropped; send the rest
        return null;
    }
}

function stopPendingSyncRetry() {
    if(state.pendingSyncTimer!==null)clearTimeout(state.pendingSyncTimer);
    state.pendingSyncTimer=null;
    state.pendingSyncRequested=false;
}

function schedulePendingSync(delay = 0) {
    delay=Math.max(delay,retryDelay(state.subject));
    if(state.pendingSyncRunning){state.pendingSyncRequested=true;return;}
    if(state.pendingSyncTimer!==null||!navigator.onLine||!state.subject||!appSessionToken())return;
    state.pendingSyncTimer=setTimeout(runPendingSyncRetry,delay);
}

async function runPendingSyncRetry() {
    state.pendingSyncTimer=null;
    if(state.pendingSyncRunning||!navigator.onLine||!state.subject||!appSessionToken())return;
    if(retryDelay(state.subject)>0){schedulePendingSync(retryDelay(state.subject));return;}
    state.pendingSyncRunning=true;
    state.pendingSyncRequested=false;
    const authentication=authenticationSnapshot();
    let pending=0;
    try {
        const owner=state.subject;
        const result=await flushPendingVault(owner);
        if(!authenticationMatches(authentication))return;
        // flushPendingVault reports failures to the UI and returns null. Do not erase the
        // Retry-After/backoff that the failed upload just recorded.
        if(result)syncRetryStates.delete(owner);
        pending=await LockstepVault.pendingCount(owner);
        if(!authenticationMatches(authentication))return;
        state.pendingChanges=pending;
        if(owner===state.subject)updateAccountSummary();
    } catch { pending=1; }
    finally {
        state.pendingSyncRunning=false;
        if((pending>0||state.pendingSyncRequested)&&navigator.onLine&&state.subject&&appSessionToken())schedulePendingSync(pending>0?TRANSIENT_RETRY_MIN_MILLIS:0);
    }
}

async function syncVault(epoch = null, allowLockedPull = false) {
    const authentication=authenticationSnapshot();
    const checkAuthentication=()=>{if(!authenticationMatches(authentication))throw Object.assign(new Error("Your sign-in changed. Try again."),{code:"SESSION_CHANGED"});};
    if(epoch!==null)assertVaultOperation(epoch);
    // This device kept an older vault that the server's replaced vault does not share: nothing is exchanged
    // with the server (its accounts cannot be opened with this key, and this key must not reach it).
    if(state.vaultReplaced)return;
    // After a quick reopen, the first sync waits for the startup answer (and its checks) and reuses its list.
    if(state.startupCheck){const check=state.startupCheck;state.startupCheck=null;await check;checkAuthentication();if(epoch!==null)assertVaultOperation(epoch);}
    checkAuthentication();
    const owner = ownerSubject();
    const prefetched = takePrefetchedVault(owner);
    if (!prefetched) {
        assertSyncCooldown(owner);
        const account = await api("/api/v1/account",{expectedAuthentication:authentication});
        if(epoch!==null)assertVaultOperation(epoch);
        if (!account.exists) {
            await LockstepVault.clearSubject(owner);
            localStorage.removeItem(`authsync.lock.${owner}`);
            const error = new Error("Your server account no longer exists. Sign in again to start fresh.");
            error.code = "ACCOUNT_MISSING";
            throw error;
        }
        if(state.bootstrapUnsupported){
            const latestLock=await api("/api/v1/lock",{expectedAuthentication:authentication});
            if(epoch!==null)assertVaultOperation(epoch);
            await applySynchronizedLock(owner,latestLock,authentication);
        }
    }
    checkAuthentication();
    let result;
    try { result=await LockstepVault.synchronize(owner, vaultTransport(owner),allowLockedPull,prefetched); syncRetryStates.delete(owner); }
    catch(error){ if(error?.notice){rememberDropNotice(error.notice);toast(error.notice,true);} throw error; }
    if(result?.notice){rememberDropNotice(result.notice);toast(result.notice,true);} // a change the server refused for good was dropped
    if(epoch!==null)assertVaultOperation(epoch);
    // Entries saved by older versions still have readable names on the server: re-save them encrypted.
    if(LockstepVault.isUnlocked(owner)&&await LockstepVault.sealPlaintextLabels(owner).catch(()=>0))schedulePendingSync(0);
    return result;
}

function renderEntrySkeleton(count = 4) {
    const entriesEl = el("entries");
    entriesEl.replaceChildren(...Array.from({ length: count }, () =>
        h("article", { className: "entry entry-skel", "aria-hidden": "true" },
            h("div", { className: "entry-view" },
                h("div", { className: "entry-heading" }, h("div", {}, h("div", { className: "skel-entry-issuer" }), h("div", { className: "skel-entry-account" }))),
                h("div", { className: "skel-entry-code" })))));
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
    state.liveRedrawPending = false;
    const hasSkeleton = el("entries").querySelector(".entry-skel") !== null;
    const isEmpty = el("entries").childElementCount === 0;
    if (hasSkeleton || isEmpty) renderEntrySkeleton();
    try {
        // Show the codes saved in this browser straight away; the server sync below then refreshes them.
        if (hasSkeleton || isEmpty) {
            let saved = [];
            try { saved = await LockstepVault.listEntries(ownerSubject()); }
            catch (error) { if (isVaultLockedError(error)) throw error; /* the sync below reports real problems */ }
            assertVaultOperation(epoch);
            if (saved.length) {
                state.entries = saved.map((entry) => ({ ...entry, pinned: state.pinnedIds.has(entry.id) }));
                sortLocalPins();
                state.serverOffsetMillis = 0;
                renderEntries();
                revealApp();
            }
        }
        try { await syncVault(epoch); assertVaultOperation(epoch);state.offline = false; state.lastSyncError = null; }
        catch (error) {
            if(epoch!==state.vaultEpoch || error.code==="SESSION_CHANGED")return;
            if(isVaultLockedError(error))throw error;
            if (error.code === "SESSION_EXPIRED" || error.code === "ACCOUNT_MISSING") {
                signOut(false, error.message);
                return;
            }
            state.offline = true;
            state.lastSyncError = error.message;
            scheduleListRetry(error);
        }
        assertVaultOperation(epoch);state.pendingChanges = await LockstepVault.pendingCount(ownerSubject());assertVaultOperation(epoch);
        const loaded = await LockstepVault.listEntries(ownerSubject());
        assertVaultOperation(epoch);
        state.entries = loaded.map((entry) => ({ ...entry, pinned: state.pinnedIds.has(entry.id) }));
        sortLocalPins();
        state.serverOffsetMillis = 0;
        renderEntries();
    } catch (error) {
        if(epoch!==state.vaultEpoch || error.code==="SESSION_CHANGED")return;
        if(isVaultLockedError(error)){showLocked();return;}
        toast(error.message, true);
        if (el("entries").querySelector(".entry-skel") !== null) el("entries").replaceChildren();
    } finally {
        if(epoch===state.vaultEpoch)state.refreshing = false;
    }
}

// A download that failed while online for a temporary reason (no connection to Lockstep, a timeout, a server
// error, "try later", or a retry delay still running) is tried again after 5 to 10 seconds (or the server's
// Retry-After), even when nothing is waiting to upload. Sign-in, validation and conflict errors are not retried.
function scheduleListRetry(error) {
    const status = Number(error?.status || 0);
    const temporary = error?.code === "SYNC_COOLDOWN" || !status || status === 408 || status === 429 || status >= 500;
    if (!temporary || !navigator.onLine) return; // going online reloads the list by itself
    clearTimeout(state.listRetryTimer);
    const owner = ownerSubject(), epoch = state.vaultEpoch;
    // Waiting out a retry delay that is already running: try again the moment it ends (it is the 5-10 s spacing).
    const spacing = error?.code === "SYNC_COOLDOWN" ? 250 : TRANSIENT_RETRY_MIN_MILLIS + Math.random() * (TRANSIENT_RETRY_MAX_MILLIS - TRANSIENT_RETRY_MIN_MILLIS);
    const delay = Math.max(error?.retryAfterMillis || 0, retryDelay(owner), spacing);
    state.listRetryTimer = setTimeout(() => {
        state.listRetryTimer = null;
        if (ownerSubject() === owner && epoch === state.vaultEpoch && isVaultOperational() && !document.hidden && navigator.onLine) loadEntries(true);
    }, delay);
}

// "6 synchronized accounts" only when nothing is waiting to upload; otherwise "6 accounts · 1 change waiting
// to sync", and when offline also why the last sync failed.
// Browsers report a lost connection as "Failed to fetch" (Chrome), "NetworkError…" (Firefox) or "Load failed" (Safari).
function friendlySyncError(message) {
    if (!navigator.onLine) return "Offline";
    if (!message || /failed to fetch|networkerror|load failed|network request failed/i.test(message)) return navigator.onLine ? "Can't reach Lockstep" : "Offline";
    if (/^(Lockstep could not sync|Sync did not finish)/.test(message)) return message;
    return `Sync failed: ${message}`;
}
function updateAccountSummary() {
    const count = state.entries.length, pending = state.pendingChanges || 0;
    const localOnly = state.entries.filter((entry) => entry.localOnly).length;
    const changes = `${pending} change${pending === 1 ? "" : "s"}`;
    const accounts = `${count} account${count === 1 ? "" : "s"}`;
    const synced = count - localOnly;
    const onlyHere = localOnly ? ` · ${localOnly} only on this device` : "";
    el("account-summary").textContent = state.offline || !navigator.onLine
        ?`${accounts} · ${friendlySyncError(state.lastSyncError)}${pending ? ` · ${changes} pending` : ""}${onlyHere}`
        : pending ? `${accounts} · ${changes} waiting to sync${onlyHere}` : `${synced} synchronized account${synced === 1 ? "" : "s"}${onlyHere}`;
}

function renderEntries() {
    document.body.classList.toggle("editing", state.editing);
    el("empty-state").classList.toggle("hidden", state.entries.length !== 0 || state.editing);
    updateAccountSummary();
    el("export-backup").disabled = state.entries.length === 0; // nothing to export yet
    // Built as elements, not HTML text: account names can never become markup (Trusted Types friendly).
    el("entries").replaceChildren(...state.entries.map((entry, index) => {
        const pinLabel = entry.pinned ? "Unpin" : "Pin";
        const broken = Boolean(entry.error);
        return h("article", { className: broken ? "entry broken" : "entry", "data-id": entry.id },
            h("div", { className: "entry-view" },
                h("div", { className: "entry-heading" },
                    h("div", { className: "entry-labels" }, h("p", { className: "issuer", title: entry.issuer }, entry.issuer), h("p", { className: "account", title: entry.accountName }, entry.accountName)),
                    entry.localOnly || entry.pinned ? h("div", { className: "entry-badges" },
                        entry.localOnly ? h("span", { className: "local-only-label", title: "This account is not on the server yet; it exists only in this browser." }, "Only on this device") : null,
                        entry.pinned ? h("span", { className: "pinned-label" }, iconNode("pin"), " Pinned") : null) : null),
                h("div", { className: "code-row" },
                    broken
                        ? h("p", { className: "entry-error", role: "note" }, entry.error)
                        : h("button", { className: "code", "data-action": "copy", title: "Copy code", "aria-label": `Copy code ${entry.code} for ${entry.issuer}` }, formatCode(entry.code)),
                    h("span", { className: "countdown" })),
                h("div", { className: "card-actions" },
                    entry.canRetry ? h("button", { "data-action": "retry-upload", "aria-label": "Upload this account again", title: "Upload again" }, iconNode("refresh")) : null,
                    entry.needsOldPassphrase ? h("button", { "data-action": "rescue", "aria-label": "Open with your previous passphrase", title: "Open with your previous passphrase" }, iconNode("lock")) : null,
                    h("button", { "data-action": "qr", "aria-label": "Show QR code", title: "Show QR code", disabled: broken }, iconNode("qr")),
                    h("button", { className: entry.pinned ? "pin-action active" : "pin-action", "data-action": "pin", "aria-label": pinLabel, title: pinLabel }, iconNode("pin")))),
            h("div", { className: "entry-edit" },
                h("button", { className: "delete-action", "data-action": "delete", "aria-label": "Remove account", title: "Remove account" }, iconNode("trash")),
                h("div", { className: "edit-fields" },
                    h("label", {}, h("span", {}, "Issuer"), h("input", { "data-field": "issuer", maxlength: "128", value: entry.issuer })),
                    h("label", {}, h("span", {}, "Account"), h("input", { "data-field": "accountName", maxlength: "256", value: entry.accountName }))),
                h("div", { className: "order-actions" },
                    // Pinned accounts stay together at the top, so a move across that boundary is not offered.
                    h("button", { "data-action": "move-up", disabled: index === 0 || Boolean(state.entries[index - 1].pinned) !== Boolean(entry.pinned), "aria-label": "Move up" }, iconNode("up")),
                    h("button", { "data-action": "move-down", disabled: index === state.entries.length - 1 || Boolean(state.entries[index + 1].pinned) !== Boolean(entry.pinned), "aria-label": "Move down" }, iconNode("down")),
                    h("button", { className: "drag-handle", draggable: "true", "aria-label": "Drag to reorder", title: "Drag to reorder" }, iconNode("grip")))),
            h("span", { className: "progress" }));
    }));
    tick();
}

// When only the codes changed (same accounts, same order), the cards are updated in place: the page is not
// rebuilt every period, so keyboard focus, hover and text selection survive a code change.
function updateCodesInPlace(next) {
    const cards = [...el("entries").querySelectorAll(".entry")];
    if (cards.length !== next.length || cards.some((card, index) => card.dataset.id !== next[index].id || card.classList.contains("entry-skel"))) return false;
    const current = new Map(state.entries.map(entry => [entry.id, entry]));
    if (next.some((entry, index) => Boolean(entry.error) !== cards[index].classList.contains("broken")
        || entry.issuer !== current.get(entry.id)?.issuer
        || entry.accountName !== current.get(entry.id)?.accountName
        || Boolean(entry.localOnly) !== Boolean(current.get(entry.id)?.localOnly)
        || Boolean(entry.canRetry) !== Boolean(current.get(entry.id)?.canRetry)
        || Boolean(entry.needsOldPassphrase) !== Boolean(current.get(entry.id)?.needsOldPassphrase)
        || entry.error !== current.get(entry.id)?.error)) return false;
    state.entries = next;
    cards.forEach((card, index) => {
        const entry = next[index], code = card.querySelector(".code");
        if (code && !entry.error) {
            const text = formatCode(entry.code);
            if (code.textContent !== text) code.textContent = text;
            code.setAttribute("aria-label", `Copy code ${entry.code} for ${entry.issuer}`);
        }
    });
    updateAccountSummary();
    tick();
    return true;
}

// Codes are generated in the browser, so a new 30-second code needs no server request.
// The background check (every 30 seconds while visible, and on return) keeps shared changes current.
async function refreshLocalCodes() {
    if (state.refreshing || state.localRefreshing || state.editing || !isVaultOperational()) return;
    let epoch;
    try { epoch = beginVaultOperation(); } catch { return; }
    state.localRefreshing = true;
    try {
        const loaded = await LockstepVault.listEntries(ownerSubject());
        assertVaultOperation(epoch);
        if (state.refreshing || state.editing) return;
        const next = loaded.map((entry) => ({ ...entry, pinned: state.pinnedIds.has(entry.id) }));
        const previous = state.entries;
        state.entries = next;
        sortLocalPins();
        state.serverOffsetMillis = 0;
        const sorted = state.entries;
        state.entries = previous;
        if (!updateCodesInPlace(sorted)) { state.entries = sorted; renderEntries(); }
    } catch (error) {
        if(epoch!==state.vaultEpoch || error.code==="SESSION_CHANGED")return;
        if (isVaultLockedError(error)) showLocked();
        else loadEntries();
    } finally {
        if(epoch===state.vaultEpoch)state.localRefreshing = false;
    }
}

// The 100 ms countdown looks entries up by ID instead of scanning the list for every card, and only
// rewrites the seconds label when it changes.
let tickIndex = { entries: null, length: -1, byId: new Map() };
function entryForTick(id) {
    if (tickIndex.entries !== state.entries || tickIndex.length !== state.entries.length) {
        tickIndex = { entries: state.entries, length: state.entries.length, byId: new Map(state.entries.map((item) => [item.id, item])) };
    }
    return tickIndex.byId.get(id) || state.entries.find((item) => item.id === id);
}

// The countdown bar is a CSS transition started once per code instead of being redrawn ten times a second.
function animateProgress(bar, entry, remaining, pending) {
    if (bar && reducedMotionPreference.matches) {
        const step = `${entry.validUntilEpochMillis}:${Math.ceil(remaining / 1000)}`;
        if (bar.dataset.step !== step) {
            bar.dataset.step = step; delete bar.dataset.until;
            bar.style.transition = "none";
            bar.style.transform = `scaleX(${remaining / (entry.period * 1000)})`;
        }
        return;
    }
    if (bar) delete bar.dataset.step;
    if (!bar || bar.dataset.until === String(entry.validUntilEpochMillis)) return;
    bar.dataset.until = String(entry.validUntilEpochMillis);
    bar.style.transition = "none";
    bar.style.transform = `scaleX(${remaining / (entry.period * 1000)})`;
    pending.push({ bar, remaining });
}

function tick() {
    const serverNow = Date.now() + state.serverOffsetMillis;
    let expired = false;
    const progress = [];
    document.querySelectorAll(".entry").forEach((node) => {
        const entry = entryForTick(node.dataset.id);
        if (!entry || !Number.isFinite(entry.validUntilEpochMillis)) return; // an account that could not be opened has no code
        const remaining = Math.max(0, entry.validUntilEpochMillis - serverNow);
        node.classList.toggle("expiring", remaining > 0 && remaining <= EXPIRING_THRESHOLD_MILLIS);
        const countdown = node.querySelector(".countdown"), label = `${Math.ceil(remaining / 1000)}s`;
        if (countdown.textContent !== label) countdown.textContent = label;
        animateProgress(node.querySelector(".progress"), entry, remaining, progress);
        if (remaining === 0) expired = true;
    });
    if (progress.length) {
        // Commit every starting width in one layout, rather than forcing a layout for every account.
        void el("entries").offsetWidth;
        for (const { bar, remaining } of progress) {
            bar.style.transition = `transform ${remaining}ms linear`;
            bar.style.transform = "scaleX(0)";
        }
    }
    if (expired && (state.token || state.subject) && !state.refreshing && !state.editing && !el("signed-in").classList.contains("hidden")) refreshLocalCodes();
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
        if (!entry.code) return;
        try {
            const epoch=beginVaultOperation();
            const current=entry.validUntilEpochMillis>Date.now()+state.serverOffsetMillis?entry:await LockstepVault.currentCode(ownerSubject(),entry.id);
            assertVaultOperation(epoch);
            if (!(current.validUntilEpochMillis>Date.now()) || !current.code) throw new Error("Code is refreshing. Try again.");
            await navigator.clipboard.writeText(current.code); toast("Code copied");
        }
        catch { toast("The code could not be copied. Select it and copy it manually.", true); }
    } else if (action === "qr") await showQr(entry);
    else if (action === "pin") await togglePin(entry.id);
    else if (action === "move-up") moveEntry(entry.id, -1);
    else if (action === "move-down") moveEntry(entry.id, 1);
    else if (action === "delete") await deleteEntry(entry);
    else if (action === "rescue") {
        const confirmed = await confirmAction({ title: "Open with your previous passphrase", label: "Open", iconName: "lock", passphrase: true,
            message: "This account was added on this device while offline, before your recovery key was rotated, and your passphrase has changed since. Enter the passphrase you used then; the account is re-encrypted with your current key and uploaded." });
        const previous = state.confirmPasskey; state.confirmPasskey = "";
        if (!confirmed || !previous) return;
        const rescued = await LockstepVault.rescueStrandedEntries(ownerSubject(), previous).catch(() => 0);
        if (rescued) { schedulePendingSync(0); await loadEntries(true); toast(`${rescued} account${rescued === 1 ? "" : "s"} re-encrypted with your current key.`); }
        else toast("That passphrase does not open this account.", true);
    }
    else if (action === "retry-upload") {
        try {
            if (await LockstepVault.retryLocalOnly(ownerSubject(), entry.id)) { toast("Uploading the account again"); schedulePendingSync(0); await loadEntries(true); }
        } catch (error) { if (!isVaultLockedError(error)) toast(error.message, true); }
    }
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
    if (!value) setTimeout(flushLiveRedraw, 0);
}

async function saveEdits() {
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    const startedAt=Date.now();
    syncDraftsFromInputs();
    if (state.entries.some((entry) => !entry.issuer.trim() || !entry.accountName.trim())) { toast("Issuer and account name are required.", true); return; }
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
        successToast("Changes saved",startedAt);
    } catch (error) { if(!isVaultLockedError(error))toast(error.message, true); }
    finally { el("save-edits").disabled = false; }
}

function syncDraftsFromInputs(event) {
    const card = event?.target?.closest?.(".entry");
    const cards = card ? [card] : document.querySelectorAll(".entry");
    const byId = card ? null : new Map(state.entries.map(entry => [entry.id, entry]));
    cards.forEach((card) => {
        const entry = byId ? byId.get(card.dataset.id) : entryForTick(card.dataset.id);
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
    const confirmed = await confirmAction({ title:"Remove account?", message:`Enter your Lockstep passphrase to remove ${entry.issuer} (${entry.accountName}) from every synchronized device.`, label:"Remove", iconName:"trash", danger:true, passphrase:true });
    const passphrase = state.confirmPasskey; state.confirmPasskey = "";
    if (!confirmed) return;
    try {
        assertVaultOperation(epoch);
        const owner=ownerSubject();
        if (!await LockstepVault.exportWrappedKey(owner)) throw new Error("Set up your vault passphrase before removing accounts.");
        if (!await LockstepVault.checkPassphrase(owner, passphrase)) throw new Error("Incorrect passphrase. Nothing was deleted.");
        if (!await ensureRecentGoogleSignIn("Confirm with Google to remove this account.")) return;
        assertVaultOperation(epoch);
        await LockstepVault.flushOutbox(owner, vaultTransport(owner));
        assertVaultOperation(epoch);
        // Retain the local entry until the authenticated server deletion is acknowledged.
        await api(`/api/v1/entries/${entry.id}`, { method:"DELETE" });
        await LockstepVault.acceptServerDeletion(owner, entry.id);
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

async function addOtpUri(otpAuthUri, { synchronize = true } = {}) {
    const epoch=beginVaultOperation(),owner=ownerSubject();
    await LockstepVault.addOtpUri(owner, otpAuthUri);
    schedulePendingSync(0);
    if(!isVaultOperational()){void flushPendingVault(owner);throw vaultLockedError();}
    assertVaultOperation(epoch);
    if(synchronize)await syncVault(epoch).catch(error=>{if(isVaultLockedError(error))throw error;});
    assertVaultOperation(epoch);
}

async function addManualEntry(event) {
    event.preventDefault(); hideInlineError("manual-error");
    const startedAt=Date.now();
    const issuer=el("manual-issuer").value.trim(), account=el("manual-account").value.trim()||nextDefaultAccountName(state.entries);
    const secret=el("manual-secret").value.toUpperCase().replace(/[\s-]/g,"");
    if(!/^[A-Z2-7]+=*$/.test(secret)){showInlineError("manual-error","The secret key can only contain the letters A-Z and the digits 2-7.");return;}
    const period=Number(el("manual-period").value);
    const query=new URLSearchParams({secret,issuer,algorithm:el("manual-algorithm").value,digits:el("manual-digits").value,period:String(period)});
    const uri=`otpauth://totp/${encodeURIComponent(`${issuer}:${account}`)}?${query}`;
    try{await addOtpUri(uri);if(!isVaultOperational())return;el("manual-form").reset();el("manual-period").value="30";el("manual-dialog").close();await loadEntries(true);if(isVaultOperational())successToast("Account added",startedAt);}
    catch(error){if(!isVaultLockedError(error))showInlineError("manual-error",error.message);}
}

async function importOtpUrls(event) {
    event.preventDefault(); hideInlineError("uri-error");
    try{beginVaultOperation();const uris=parseBackup(el("otp-uris").value);const result=await importUris(uris);if(!isVaultOperational())return;el("uri-form").reset();el("uri-dialog").close();await loadEntries(true);if(isVaultOperational())toast(result.failed?`${result.imported} imported; ${result.failed} failed.`:`${result.imported} account${result.imported===1?"":"s"} imported.`,result.failed>0);}
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
    await loadVendorScript("jsQR").catch(() => null);
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
        el("camera-status").textContent="This QR code is not an authenticator (TOTP) code. Choose a different QR code and try again.";
        el("camera-status").classList.add("is-error");
        cameraScanner.ignoreUntil=Date.now()+600;
    } catch {
        cameraScanner.processing=false;
        el("camera-status").textContent="This QR code is not an authenticator (TOTP) code. Choose a different QR code and try again.";
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
        el("camera-status").textContent="This QR code is not an authenticator (TOTP) code. Choose a different QR code and try again.";
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
        toast("Account added");
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
        await loadVendorScript("jsQR").catch(() => null);
        const uris=[];let firstError="";
        for(const file of files){assertVaultOperation(epoch);let loaded;try{loaded=await loadQrImage(file);assertVaultOperation(epoch);const uri=detectTotpQr(loaded.source);if(uri)uris.push(uri);}catch(error){if(isVaultLockedError(error))throw error;firstError ||= error.message;}finally{loaded?.close();}await new Promise(requestAnimationFrame);}
        if (!uris.length) throw new Error(firstError||"No TOTP QR code was found in the selected images.");
        assertVaultOperation(epoch);
        const result=await importUris(uris),unreadable=files.length-uris.length;
        closeAdd();await loadEntries(true);toast(`${result.imported} imported${unreadable?`; ${unreadable} image${unreadable===1?"":"s"} unreadable`:""}.`,unreadable>0||result.failed>0);
    } catch (error) { clearToast();if(!isVaultLockedError(error))showInlineError("add-error", error.message); }
    finally { event.target.value = ""; }
}

// Imported accounts are saved locally one by one, then synchronized once (in batches) at the end.
async function importUris(uris){
    const authentication=authenticationSnapshot(),owner=ownerSubject(),epoch=beginVaultOperation();
    let imported=0,failed=0;
    const check=()=>{
        if(!authenticationMatches(authentication))throw Object.assign(new Error("Your sign-in changed. Import stopped."),{code:"SESSION_CHANGED"});
        assertVaultOperation(epoch);
    };
    try {
        for(const uri of uris){
            check();
            try{await LockstepVault.addOtpUri(owner,uri);imported++;}
            catch(error){if(isVaultLockedError(error)||["SESSION_CHANGED","SESSION_EXPIRED","SESSION_REVOKED"].includes(error.code))throw error;failed++;}
            check();schedulePendingSync(0);
        }
        if(imported>0){check();await syncVault(epoch).catch(error=>{if(isVaultLockedError(error)||error.code==="SESSION_CHANGED")throw error;});check();}
    }catch(error){error.message+=` ${imported} account${imported===1?" was":"s were"} imported into the original vault before stopping; ${failed} failed.`;throw error;}
    return {imported,failed};
}
async function loadQrImage(file) { return LockstepImages.load(file); }
function detectTotpQr(image) {
    if (typeof window.jsQR !== "function") throw new Error("The QR scanner could not be loaded. Reload Lockstep and try again.");
    const sourceWidth=image.videoWidth||image.naturalWidth||image.width,sourceHeight=image.videoHeight||image.naturalHeight||image.height;
    if(!sourceWidth||!sourceHeight)throw new Error("This image could not be read.");
    const maxDimension=1600,scale=Math.min(1,maxDimension/Math.max(sourceWidth,sourceHeight));
    const canvas = document.createElement("canvas"); canvas.width=Math.max(1,Math.round(sourceWidth*scale)); canvas.height=Math.max(1,Math.round(sourceHeight*scale));
    const context=canvas.getContext("2d",{willReadFrequently:true});context.drawImage(image,0,0,sourceWidth,sourceHeight,0,0,canvas.width,canvas.height);
    const pixels=context.getImageData(0,0,canvas.width,canvas.height);
    let decoded=window.jsQR(pixels.data,pixels.width,pixels.height,{inversionAttempts:"dontInvert"});
    if(!decoded)decoded=window.jsQR(pixels.data,pixels.width,pixels.height,{inversionAttempts:"attemptBoth"});
    return decoded?.data?.startsWith("otpauth://totp/") ? decoded.data : null;
}

// Each opening of the QR dialog gets its own number. A QR code that finishes after the dialog was closed (or
// reopened for another account) is dropped, so it can neither show the wrong account's secret nor stay
// behind in a closed dialog.
let qrRequest = 0;
async function showQr(entry) {
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    const request = ++qrRequest;
    const current = () => request === qrRequest && el("qr-dialog").open;
    el("qr-title").textContent = entry.issuer; el("qr-account").textContent = entry.accountName;
    el("qr-loading").textContent = ""; el("qr-loading").classList.add("hidden"); el("qr-skeleton").classList.remove("hidden"); el("qr-image").classList.add("hidden"); el("qr-image").removeAttribute("src");
    if (!el("qr-dialog").open) el("qr-dialog").showModal();
    try {
        const uri = await LockstepVault.otpAuthUri(ownerSubject(), entry.id);
        assertVaultOperation(epoch);
        if (!current()) return;
        await loadVendorScript("QRCode").catch(() => null);
        assertVaultOperation(epoch);
        if (!current()) return;
        if (!globalThis.QRCode?.toDataURL) throw new Error("The QR code could not be shown. Reload Lockstep and try again.");
        const source=await globalThis.QRCode.toDataURL(uri, { errorCorrectionLevel: "M", margin: 2, width: 320 });assertVaultOperation(epoch);
        if (!current()) return;
        el("qr-image").src = source;
        el("qr-skeleton").classList.add("hidden"); el("qr-image").classList.remove("hidden"); el("qr-loading").classList.add("hidden");
    } catch (error) { if(!isVaultLockedError(error)&&current()){el("qr-skeleton").classList.add("hidden"); el("qr-loading").textContent = error.message; el("qr-loading").classList.remove("hidden");} }
}
function clearQrDialog() { qrRequest++; const source=el("qr-image").src; if(source.startsWith("blob:")) URL.revokeObjectURL(source); el("qr-skeleton").classList.remove("hidden"); el("qr-loading").classList.add("hidden"); el("qr-image").removeAttribute("src"); el("qr-image").classList.add("hidden"); }

// Exports confirm the vault passphrase first (checked on this device), so someone at an unlocked, unattended
// browser cannot walk away with every secret.
const DOWNLOADS_WARNING="Downloads folders are often synced to cloud storage, so keep the file somewhere private.";
async function confirmExportWithPassphrase(title,message,label,iconName){
    const confirmed=await confirmAction({title,message,label,iconName,passphrase:true});
    const passphrase=state.confirmPasskey; state.confirmPasskey="";
    if(!confirmed)return false;
    if(await LockstepVault.checkPassphrase(ownerSubject(),passphrase))return true;
    toast("Incorrect passphrase.",true);
    return false;
}

// The backup-password dialog. Export: choose a password (or download without one). Import: enter the
// password of an encrypted backup. `accept` runs on submit; an error it throws is shown and the dialog stays open.
function askBackupPassword({mode,accept}){
    const dialog=el("backup-dialog"),exporting=mode==="export";
    el("backup-title").textContent=exporting?"Protect the backup file":"Encrypted backup";
    el("backup-message").textContent=exporting
        ?`Choose a password of at least 12 characters to encrypt the file. Without one, anyone who opens the file can copy every code. ${DOWNLOADS_WARNING}`
        :"Enter the password this backup was protected with.";
    el("backup-password").value="";el("backup-password-confirm").value="";
    el("backup-password").autocomplete=exporting?"new-password":"current-password";
    el("backup-password-confirm").classList.toggle("hidden",!exporting);
    el("backup-plain").classList.toggle("hidden",!exporting);
    el("backup-accept").textContent=exporting?"Encrypt and download":"Open backup";
    el("backup-accept").disabled=false;
    hideInlineError("backup-error");
    return new Promise((resolve)=>{
        let settled=false,submitting=false;
        const finish=(value)=>{if(settled)return;settled=true;dialog.onclose=null;el("backup-form").onsubmit=null;el("backup-cancel").onclick=null;el("backup-plain").onclick=null;el("backup-password").value="";el("backup-password-confirm").value="";if(dialog.open)dialog.close();resolve(value);};
        dialog.onclose=()=>finish(null);
        el("backup-cancel").onclick=()=>finish(null);
        el("backup-plain").onclick=()=>finish({plain:true});
        el("backup-form").onsubmit=async(event)=>{
            event.preventDefault();if(settled||submitting)return;hideInlineError("backup-error");
            const password=el("backup-password").value;
            if(exporting&&password!==el("backup-password-confirm").value){showInlineError("backup-error","The passwords do not match.");return;}
            submitting=true;el("backup-accept").disabled=true;
            try{const value=await accept(password);finish(value);}
            catch(error){if(!settled)showInlineError("backup-error",error.message);}
            finally{if(!settled){submitting=false;el("backup-accept").disabled=false;}}
        };
        dialog.showModal();el("backup-password").focus();
    });
}

function downloadFile(text,name,type){
    const url=URL.createObjectURL(new Blob([text],{type})),link=document.createElement("a");
    link.href=url;link.download=name;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
}

async function exportBackup() {
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    try {
        if(!await confirmExportWithPassphrase("Export authenticator backup?",`The file contains the secrets needed to generate every code. Enter your passphrase to continue. ${DOWNLOADS_WARNING}`,"Continue","export"))return;
        assertVaultOperation(epoch);
        const date=new Date().toISOString().slice(0,10);
        const text=await LockstepVault.exportText(ownerSubject());assertVaultOperation(epoch);
        const result=await askBackupPassword({mode:"export",accept:async(password)=>{
            if(password.length<12)throw new Error("Use at least 12 characters, or choose No password.");
            return {encrypted:await LockstepVault.encryptBackup(text,password)};
        }});
        assertVaultOperation(epoch);
        if(!result)return;
        if(result.encrypted)downloadFile(result.encrypted,`lockstep-backup-${date}.json`,"application/json");
        else downloadFile(text,`lockstep-totp-backup-${date}.txt`,"text/plain;charset=utf-8");
        toast(result.encrypted?"Encrypted backup exported":"Backup exported");
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
        if(!await confirmExportWithPassphrase("Download recovery key?",`Anyone with the recovery key can restore and decrypt your vault. Enter your passphrase to continue. ${DOWNLOADS_WARNING}`,"Download","lock"))return;
        assertVaultOperation(epoch);
        const config = await api("/api/v1/lock");
        assertVaultOperation(epoch);
        if (await LockstepVault.synchronizeWrappedKey(ownerSubject(), config.wrappedKey, config.vaultRevision)) {
            state.lockConfig = config;
            lockApp();
            toast("Your passphrase changed on another device. Unlock again before downloading the recovery key.", true);
            return;
        }
        const recoveryKey=await LockstepVault.exportRecoveryKey(ownerSubject());assertVaultOperation(epoch);downloadRecoveryKeyFile(recoveryKey);
        toast("Recovery key downloaded. Store it somewhere private.");
    } catch (error) { if(!isVaultLockedError(error))toast(error.message, true); }
}

// The server's vault was replaced outside Lockstep (see LockstepVault.serverVaultReplaced): take the server's
// key when nothing would be lost. Returns true when adopted (the vault must be unlocked again with the
// server's passphrase); throws the reason when this device still holds something the server does not.
async function adoptReplacedServerVault(owner, lock) {
    if (!await LockstepVault.serverVaultReplaced(owner, lock?.wrappedKey, lock?.vaultRevision)) return false;
    const serverEntries = await api("/api/v1/entries");
    return LockstepVault.adoptReplacedServerVault(owner, lock.wrappedKey, lock.vaultRevision, serverEntries.map((entry) => entry.id));
}

async function rotateEncryptionKey() {
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    const settingsWasOpen = el("settings-dialog").open;
    if (settingsWasOpen) el("settings-dialog").close();
    const confirmed = await confirmAction({ title:"Rotate recovery key?", message:"A brand-new recovery key is generated and every account is re-encrypted with it. The new recovery key will be downloaded; your old recovery key stops working. Other devices lock when they detect this change and use the new key after unlocking with your current passphrase. Enter your passphrase to continue.", label:"Rotate recovery key", iconName:"lock", passphrase:true });
    const passphrase = state.confirmPasskey; state.confirmPasskey = "";
    // Settings reopen only while the vault is still open: a lock from another device (which also closes this
    // question) must leave the lock screen in front.
    const reopenSettings = () => { if (settingsWasOpen && isVaultOperational()) openSettings(); };
    if (!confirmed) { reopenSettings(); return; }
    if (passphrase.length < 4) { toast("Enter your passphrase to rotate the recovery key.", true); reopenSettings(); return; }
    if (!await ensureRecentGoogleSignIn("Confirm with Google to rotate your recovery key.")) return;
    toast("Rotating recovery key…", false, true);
    let sentToServer = false;
    try {
        assertVaultOperation(epoch);
        const owner = ownerSubject();
        // Refresh before proving the action passphrase: another device may have changed the key
        // since the last ordinary synchronization, advancing the vault revision.
        const latestLock = await api("/api/v1/lock");
        assertVaultOperation(epoch);
        let keyChanged;
        try { keyChanged = await LockstepVault.refreshRotationKey(owner, latestLock.wrappedKey, latestLock.vaultRevision, passphrase); }
        catch (error) {
            // A different key on the server: if its vault replaced this device's older one, take it (unless that
            // would lose accounts or changes that only this device has), then continue.
            if (error.code !== "VAULT_STATE_MISMATCH") throw error;
            try { if (!await adoptReplacedServerVault(owner, latestLock)) throw error; }
            catch (adoptError) {
                if (adoptError.code === "VAULT_REPLACED") throw new Error(`${adoptError.message} Lock and unlock Lockstep to choose what to do with them before rotating.`);
                throw adoptError;
            }
            keyChanged = true;
        }
        if (keyChanged) {
            // Prove the supplied passphrase opens the current server key before preparing any rotation
            // (a key taken from the server is not open yet, so this comes before the next vault check).
            try { await LockstepVault.unlock(owner, passphrase); }
            catch (error) { lockApp(); throw error; }
        }
        assertVaultOperation(epoch);
        state.lockConfig = normalizeLockConfig(latestLock);
        localStorage.setItem(`authsync.lock.${owner}`, JSON.stringify(state.lockConfig));
        persistUnlockedSession();
        await syncVault(epoch); // must be online and fully synced before the key changes
        assertVaultOperation(epoch);
        // 1. Re-encrypt everything in memory only. Until step 3 (or a failure), no other change can be made here.
        const prepared = await LockstepVault.prepareMasterRotation(owner, passphrase);
        // 2. The server swaps the wrapped key and every entry in one transaction (or refuses if the vault changed).
        let response;
        try {
            assertVaultOperation(epoch);
            sentToServer = true;
            response = await api("/api/v1/vault/rotate", { method:"POST", body:JSON.stringify({
                timeoutSeconds:state.lockConfig.timeoutSeconds || 300, lockOnScreenLock:Boolean(state.lockConfig.lockOnScreenLock),
                wrappedKey:prepared.wrappedKey, entries:prepared.entries.map(entry => ({ id:entry.id, entry })), previous:prepared.previous,
                expectedRevision:prepared.expectedRevision }) });
        } catch (error) {
            LockstepVault.cancelMasterRotation(prepared); // this device keeps its current key
            if (error.status === 404 || error.status === 405) { sentToServer = false; throw new Error("Update the Lockstep server before rotating the recovery key."); }
            if (error.status === 409 || error.status === 400 || error.status === 413 || error.status === 429) sentToServer = false; // refused: nothing changed anywhere
            throw error;
        }
        // 3. Only now store the new key and entries on this device, then save the new recovery key.
        const result = await LockstepVault.commitMasterRotation(prepared, response.entries, response.lock?.vaultRevision);
        state.lockConfig = normalizeLockConfig(response.lock);
        localStorage.setItem(`authsync.lock.${owner}`, JSON.stringify(state.lockConfig));
        persistUnlockedSession();
        downloadRecoveryKeyFile(result.recoveryKey);
        await loadEntries(true);
        toast(`Recovery key rotated to version ${result.version} and downloaded; store it somewhere private.`);
    } catch (error) {
        if(isVaultLockedError(error))return;
        if (sentToServer) toast(`The rotation could not be confirmed (${error.message}). If it went through, this device picks up the new key the next time you unlock; then download your recovery key from Settings.`, true);
        else toast(error.message, true);
    }
}
async function importBackup(event) {
    const file=event.target.files?.[0]; event.target.value=""; if(!file)return;
    let epoch;try{epoch=beginVaultOperation();}catch{return;}
    try {
        if(file.size>MAX_BACKUP_FILE_BYTES)throw new Error("This file is too large to be a Lockstep backup (at most 8 MB).");
        const text=await file.text();assertVaultOperation(epoch);
        const uris=parseBackup(await backupText(text));assertVaultOperation(epoch);if(!uris)return;toast(`Importing ${uris.length} account${uris.length===1?"":"s"}…`);const {imported,failed}=await importUris(uris);assertVaultOperation(epoch);
        await loadEntries(true); toast(failed?`${imported} imported; ${failed} failed.`:`${imported} account${imported===1?"":"s"} imported.`,failed>0);
    } catch(error){if(!isVaultLockedError(error))toast(error.message,true);}
}
// An encrypted backup asks for its password and returns the "otpauth://" text inside; null when cancelled.
async function backupText(text){
    if(!LockstepVault.isEncryptedBackup(text))return text;
    return askBackupPassword({mode:"import",accept:(password)=>LockstepVault.decryptBackup(text,password)});
}
function parseBackup(text) {
    if(text===null)return null;
    const uris=text.split(/\r?\n/).map((line)=>line.trim()).filter((line)=>line&&!line.startsWith("#"));
    if(!uris.length)throw new Error("This backup does not contain any TOTP entries."); if(uris.length>1000)throw new Error("A backup can contain at most 1000 entries.");
    const invalid=uris.findIndex((line)=>!line.startsWith("otpauth://totp/")); if(invalid>=0)throw new Error(`Not an otpauth://totp/ URL: "${uris[invalid].length>48?uris[invalid].slice(0,48)+"…":uris[invalid]}"`); return uris;
}
function nextDefaultAccountName(items){const highest=items.reduce((maximum,item)=>{const match=/^Account (\d+)$/.exec(item.accountName||"");return match?Math.max(maximum,Number(match[1])):maximum;},0);return `Account ${highest+1}`;}

function lockTimestampKey(){return `authsync.unlocked.${ownerSubject()}`;}
function sessionKeyStorageKey(){return `authsync.session-key.${ownerSubject()}`;}
function normalizeLockConfig(config){const timeout=Number(config?.timeoutSeconds);return{...(config||{}),enabled:Boolean(config?.enabled),timeoutSeconds:LOCK_TIMEOUT_LABELS.has(timeout)?timeout:300,lockOnScreenLock:Boolean(config?.lockOnScreenLock)};}
// Identifies this tab's key for the sealed copy of the unlocked vault key (see LockstepVault.exportSessionKey).
const SESSION_TAB_KEY="authsync.session-tab";
function sessionTabKey(){let key=sessionStorage.getItem(SESSION_TAB_KEY);if(!key){key=crypto.randomUUID();sessionStorage.setItem(SESSION_TAB_KEY,key);}return key;}
function persistUnlockedSession(){
    if(!state.lockConfig.enabled){sessionStorage.removeItem(sessionKeyStorageKey());return;}
    const owner=ownerSubject(),storageKey=sessionKeyStorageKey();
    LockstepVault.exportSessionKey(owner,sessionTabKey()).then(snapshot=>{
        // Saved only if the vault is still open for the same account (it may have locked meanwhile).
        if(!snapshot||ownerSubject()!==owner||!LockstepVault.isUnlocked(owner))return;
        const value=JSON.stringify(snapshot);
        if(sessionStorage.getItem(storageKey)!==value)sessionStorage.setItem(storageKey,value);
    }).catch(()=>null);
}
async function resumeUnlockedSession(){
    if(!state.lockConfig.enabled)return false;
    const lastActivity=Number(sessionStorage.getItem(lockTimestampKey())||0);
    if(!lastActivity||Date.now()-lastActivity>=state.lockConfig.timeoutSeconds*1000){clearUnlockedSession();return false;}
    if(!LockstepVault.isUnlocked(ownerSubject())){
        try{
            const snapshot=JSON.parse(sessionStorage.getItem(sessionKeyStorageKey())||"null");
            if(!await LockstepVault.restoreSessionKey(ownerSubject(),snapshot,sessionTabKey())){clearUnlockedSession();return false;}
            if(snapshot?.raw)persistUnlockedSession(); // replace a copy saved by the previous version with a sealed one
        }catch{clearUnlockedSession();return false;}
    }
    state.lastActivityAt=lastActivity;
    return true;
}
function clearUnlockedSession(){
    if(state.token||state.subject){
        sessionStorage.removeItem(lockTimestampKey());sessionStorage.removeItem(sessionKeyStorageKey());
        LockstepVault.forgetSessionKey(ownerSubject(),sessionStorage.getItem(SESSION_TAB_KEY)).catch(()=>null);
    }
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
function updateLockSummary(){const duration=LOCK_TIMEOUT_LABELS.get(state.lockConfig.timeoutSeconds)||"inactivity";el("lock-summary").textContent=state.lockConfig.enabled?`Locks after ${duration}${state.lockConfig.lockOnScreenLock?" or when the screen locks":""}`:"Protect codes with a passphrase";void syncScreenLockWatch();}
function recordPointerActivity(){const now=Date.now();if(now-state.lastPointerActivityAt<1000)return;state.lastPointerActivityAt=now;recordUserActivity();}
function recordUserActivity(){if((!state.token&&!state.subject)||el("signed-in").classList.contains("hidden"))return;state.lastActivityAt=Date.now();sessionStorage.setItem(lockTimestampKey(),String(state.lastActivityAt));persistUnlockedSession();scheduleInactivityLock();}
function scheduleInactivityLock(){stopInactivityWatch();if(!state.lockConfig.enabled)return;const remaining=Math.max(0,state.lockConfig.timeoutSeconds*1000-(Date.now()-state.lastActivityAt));state.inactivityTimer=setTimeout(enforceInactivityLock,remaining);}
function stopInactivityWatch(){if(state.inactivityTimer!==null){clearTimeout(state.inactivityTimer);state.inactivityTimer=null;}}
function enforceInactivityLock(){if((!state.token&&!state.subject)||!state.lockConfig.enabled||!el("locked").classList.contains("hidden"))return;const stored=Number(sessionStorage.getItem(lockTimestampKey())||state.lastActivityAt||0);if(Date.now()-stored>=state.lockConfig.timeoutSeconds*1000)lockApp();else{state.lastActivityAt=stored;scheduleInactivityLock();}}
function lockApp(){
    if(!state.token&&!state.subject)return;
    state.lockEpoch=(state.lockEpoch||0)+1; // an unlock still running when this happens gives up (see unlockApp)
    cancelVaultOperations(false);
    state.vaultReplaced=false;
    LockstepVault.lock(ownerSubject());
    clearUnlockedSession();
    closeVaultSurfaces();
    showLocked();
    schedulePendingSync(0);
}
async function unlockApp(event){
    event.preventDefault();hideInlineError("unlock-error");
    const epoch=state.lockEpoch||0;
    try{
        const owner=ownerSubject(),passcode=el("unlock-passcode").value;
        let serverConfig=null,replacedNotice=null;
        try{
            serverConfig=await api("/api/v1/lock");await LockstepVault.synchronizeWrappedKey(owner,serverConfig.wrappedKey,serverConfig.vaultRevision);
            // The server's vault was replaced outside Lockstep: take its key now when nothing would be lost;
            // otherwise keep this device's key so its accounts can still be opened and exported.
            try{await adoptReplacedServerVault(owner,serverConfig);}
            catch(error){
                if(error.code!=="VAULT_REPLACED")throw error;
                const replace=await confirmAction({title:"Use the server's vault?",message:`${error.message} Use the server's vault to replace this device's copy (export a backup first if you still need those accounts), or cancel to keep it for now.`,label:"Use server's vault",iconName:"lock",danger:true});
                if(replace)await LockstepVault.adoptReplacedServerVault(owner,serverConfig.wrappedKey,serverConfig.vaultRevision,[],{force:true});
                else replacedNotice="This device kept its older vault. Export what you need, then lock and unlock again to switch to the server's vault.";
            }
        }
        catch(error){if(error.code==="SESSION_EXPIRED")throw error;}
        if(!serverConfig){
            try{serverConfig=JSON.parse(localStorage.getItem(`authsync.lock.${owner}`));}catch{/* handled below */}
        }
        if(!serverConfig)throw new Error("Can't reach Lockstep. Unlock this vault online once before using it offline.");
        await LockstepVault.unlock(owner,passcode);
        // Locked again (screen lock, sign-out) while this unlock was still running: the lock wins.
        if((state.lockEpoch||0)!==epoch){LockstepVault.lock(owner);showLocked();return;}
        state.vaultReplaced=Boolean(replacedNotice);
        // Accounts added offline before the recovery key was rotated elsewhere: re-encrypt them with the new key.
        const rescued=replacedNotice?0:await LockstepVault.rescueStrandedEntries(owner,passcode).catch(()=>0);
        if(replacedNotice)toast(replacedNotice,true); // this device keeps its own key: nothing below is uploaded
        state.lockConfig=normalizeLockConfig({...serverConfig,enabled:true});
        // With Argon2id switched on, re-protect a PBKDF2 vault while a fresh Google sign-in allows saving it.
        if(!replacedNotice&&serverConfig.wrappedKey&&Number.isInteger(serverConfig.vaultRevision)&&hasRecentGoogleSignIn())await LockstepVault.upgradeWrapping(owner,passcode).catch(()=>false);
        // Without a recent Google sign-in the upgrade cannot be saved yet: offer it once per browser session.
        const offerUpgrade=!replacedNotice&&serverConfig.wrappedKey&&Number.isInteger(serverConfig.vaultRevision)&&!hasRecentGoogleSignIn()
            &&sessionStorage.getItem("authsync.upgradeOffered")!=="1"&&await LockstepVault.needsWrappingUpgrade(owner,passcode).catch(()=>false);
        if(replacedNotice){/* keep this device's own key; see above */}
        else if(serverConfig.wrappedKey&&Number.isInteger(serverConfig.vaultRevision)){
            // A passphrase change or recovery-key import saved here but not yet on the server is uploaded now,
            // expecting the server revision it was based on. If another device changed the key since, the
            // server refuses it and this device takes the server's key instead (it never overwrites it).
            const pending=await LockstepVault.pendingWrappedKeyUpload(owner);
            if(pending){
                try{
                    state.lockConfig=normalizeLockConfig(await api("/api/v1/lock",{method:"PUT",body:JSON.stringify({timeoutSeconds:state.lockConfig.timeoutSeconds||300,lockOnScreenLock:Boolean(state.lockConfig.lockOnScreenLock),wrappedKey:pending.wrappedKey,expectedRevision:pending.expectedRevision})}));
                    await LockstepVault.markWrappedKeySynced(owner,state.lockConfig.vaultRevision,state.lockConfig.wrappedKey);
                }catch(error){
                    if(error.code==="SESSION_EXPIRED")throw error;
                    if(error.status===409&&await adoptServerKeyAfterConflict(owner)){showInlineError("unlock-error","Your passphrase was changed on another device. Unlock with the current passphrase.");return;}
                    // Saving the changed key needs a recent Google sign-in; otherwise it stays saved here and is retried.
                    if(error.code==="REAUTH_REQUIRED"&&await ensureRecentGoogleSignIn("Confirm with Google to finish saving your new passphrase.")){
                        try{
                            state.lockConfig=normalizeLockConfig(await api("/api/v1/lock",{method:"PUT",body:JSON.stringify({timeoutSeconds:state.lockConfig.timeoutSeconds||300,lockOnScreenLock:Boolean(state.lockConfig.lockOnScreenLock),wrappedKey:pending.wrappedKey,expectedRevision:pending.expectedRevision})}));
                            await LockstepVault.markWrappedKeySynced(owner,state.lockConfig.vaultRevision,state.lockConfig.wrappedKey);
                        }catch(retryError){if(retryError.status===409&&await adoptServerKeyAfterConflict(owner)){showInlineError("unlock-error","Your passphrase was changed on another device. Unlock with the current passphrase.");return;}}
                    }
                }
            }
        }else if(serverConfig.wrappedKey){
            // Older servers without revisions: the previous rule (the newer wrapped key wins) still applies.
            const localWrapped=await LockstepVault.exportWrappedKey(owner);
            const remoteAt=Number(serverConfig.wrappedKey.wrappedAt||serverConfig.wrappedKey.createdAt||0);
            if(localWrapped&&Number(localWrapped.wrappedAt||localWrapped.createdAt||0)>remoteAt){
                state.lockConfig=await api("/api/v1/lock",{method:"PUT",body:JSON.stringify({timeoutSeconds:state.lockConfig.timeoutSeconds||300,lockOnScreenLock:Boolean(state.lockConfig.lockOnScreenLock),wrappedKey:localWrapped})}).catch(()=>state.lockConfig);
            }
        }
        localStorage.setItem(`authsync.lock.${owner}`,JSON.stringify(state.lockConfig));
        if((state.lockEpoch||0)!==epoch){LockstepVault.lock(owner);showLocked();return;} // locked during the server checks
        el("unlock-passcode").value="";state.lastActivityAt=Date.now();sessionStorage.setItem(lockTimestampKey(),String(state.lastActivityAt));persistUnlockedSession();
        await showUnlockedApp();
        if((state.lockEpoch||0)!==epoch||owner!==state.subject||!isVaultOperational())return;
        if(replacedNotice)toast(replacedNotice,true,true);else toast(rescued?`Vault unlocked. ${rescued} account${rescued===1?"":"s"} added offline ${rescued===1?"was":"were"} re-encrypted with your new recovery key.`:"Vault unlocked");
        if(rescued)schedulePendingSync(0);
        if(offerUpgrade){sessionStorage.setItem("authsync.upgradeOffered","1");void offerProtectionUpgrade(owner,passcode);}
    }catch(error){if(error.code==="KEY_MISSING")signOut(false,"Local vault data was cleared. Sign in with Google again.");else if(error.code==="SESSION_EXPIRED")signOut(false,error.message);else showInlineError("unlock-error",error.message);}
}
async function openLockSettings({required=false,refresh=true}={}){try{if(refresh)state.lockConfig=normalizeLockConfig(await api("/api/v1/lock"));state.lockSetupRequired=required;updateLockSummary();el("lock-form").reset();el("lock-timeout").value=String(state.lockConfig.timeoutSeconds||300);el("lock-on-screen-lock").checked=Boolean(state.lockConfig.lockOnScreenLock);el("lock-dialog-title").textContent=required?"Create lock protection":"Change lock protection";el("lock-dialog-description").textContent=required?"Create a passphrase before adding or viewing authenticator accounts. When setup finishes, your recovery-key file downloads automatically.":"Choose a new passphrase and when Lockstep should lock.";el("lock-dialog-close").classList.toggle("hidden",required);hideInlineError("lock-error");el("settings-dialog").close();el("lock-dialog").showModal();el("lock-passcode").focus();}catch(error){if(!isVaultLockedError(error))toast(error.message,true);}}
async function saveLockSettings(event){
    event.preventDefault();hideInlineError("lock-error");
    const lockOnScreenLock=el("lock-on-screen-lock").checked;
    if(lockOnScreenLock){
        if(!("IdleDetector" in window)){showInlineError("lock-error","Screen-lock detection is not supported by this browser.");return;}
        try{if(await IdleDetector.requestPermission()!=="granted"){showInlineError("lock-error","Allow screen-lock detection to enable this option.");return;}}
        catch{showInlineError("lock-error","Screen-lock detection could not be enabled in this browser.");return;}
    }
    const initialSetup=state.lockSetupRequired;
    let epoch=null;try{if(state.lockConfig.enabled)epoch=beginVaultOperation();}catch{return;}
    const passcode=el("lock-passcode").value;
    if(passcode.length<NEW_PASSPHRASE_MIN_LENGTH){showInlineError("lock-error",`Passphrase must contain at least ${NEW_PASSPHRASE_MIN_LENGTH} characters.`);return;}
    if(passcode!==el("lock-confirm").value){showInlineError("lock-error","Passphrases do not match.");return;}
    // Changing an existing passphrase replaces the key other devices use: confirm with Google first.
    if(!initialSetup&&state.lockConfig.wrappedKey&&!await ensureRecentGoogleSignIn("Confirm with Google to change your passphrase."))return;
    // The Google confirmation can take a while; the vault may have locked meanwhile (for example the passphrase was
    // changed on another device). Then nothing is changed here and the lock screen explains why.
    if(epoch!==null&&(epoch!==state.vaultEpoch||!isVaultOperational()))return;
    try{
        await LockstepVault.configurePassphrase(ownerSubject(),passcode);if(epoch!==null)assertVaultOperation(epoch);
        const wrappedKey=await LockstepVault.exportWrappedKey(ownerSubject());if(epoch!==null)assertVaultOperation(epoch);
        const expectedRevision=await LockstepVault.expectedRevision(ownerSubject());
        try{
            state.lockConfig=normalizeLockConfig(await api("/api/v1/lock",{method:"PUT",body:JSON.stringify({timeoutSeconds:Number(el("lock-timeout").value),lockOnScreenLock,wrappedKey,expectedRevision})}));
        }catch(error){
            // Another device changed the passphrase or rotated the key meanwhile: take its key, do not overwrite it.
            if(error.status===409){el("lock-dialog").close();if(await adoptServerKeyAfterConflict(ownerSubject()))toast(error.message,true);else showInlineError("lock-error",error.message);return;}
            throw error;
        }
        await LockstepVault.markWrappedKeySynced(ownerSubject(),state.lockConfig.vaultRevision,state.lockConfig.wrappedKey);
        localStorage.setItem(`authsync.lock.${ownerSubject()}`,JSON.stringify(state.lockConfig)); // also lets the next start open without waiting
        if(epoch!==null)assertVaultOperation(epoch);
        const recoveryKey=initialSetup?await LockstepVault.exportRecoveryKey(ownerSubject()):null;if(epoch!==null)assertVaultOperation(epoch);
        state.lastActivityAt=Date.now();sessionStorage.setItem(lockTimestampKey(),String(state.lastActivityAt));persistUnlockedSession();
        el("lock-passcode").value="";el("lock-confirm").value="";state.lockSetupRequired=false;updateLockSummary();el("lock-dialog").close();el("lock-now").classList.remove("hidden");
        if(recoveryKey){downloadRecoveryKeyFile(recoveryKey);toast("Profile setup complete. Recovery key downloaded; store it somewhere private.");}else toast("Lock protection saved");
        scheduleInactivityLock();await loadEntries(true);
    }catch(error){if(!isVaultLockedError(error))showInlineError("lock-error",error.message);}
}

// Re-protects a PBKDF2 vault with Argon2id (memory-hard, much slower to guess offline). Saving the re-wrapped
// key replaces the one other devices use, so it needs a Google confirmation.
async function offerProtectionUpgrade(owner,passcode){
    try{
        const accepted=await confirmAction({title:"Strengthen vault protection?",message:"Your passphrase protects the vault key with an older method. Lockstep can switch it to Argon2id, which makes your passphrase much harder to guess if the encrypted vault is ever stolen. Your passphrase stays the same. You'll be asked to confirm with Google.",label:"Upgrade",iconName:"shield"});
        if(!accepted||!await ensureRecentGoogleSignIn("Confirm with Google to strengthen your vault protection."))return;
        if(!await LockstepVault.upgradeWrapping(owner,passcode))return;
        const pending=await LockstepVault.pendingWrappedKeyUpload(owner);
        if(!pending)return;
        state.lockConfig=normalizeLockConfig(await api("/api/v1/lock",{method:"PUT",body:JSON.stringify({timeoutSeconds:state.lockConfig.timeoutSeconds||300,lockOnScreenLock:Boolean(state.lockConfig.lockOnScreenLock),wrappedKey:pending.wrappedKey,expectedRevision:pending.expectedRevision})}));
        await LockstepVault.markWrappedKeySynced(owner,state.lockConfig.vaultRevision,state.lockConfig.wrappedKey);
        localStorage.setItem(`authsync.lock.${owner}`,JSON.stringify(state.lockConfig));
        persistUnlockedSession();
        toast("Vault protection upgraded to Argon2id");
    }catch(error){
        if(error.status===409&&await adoptServerKeyAfterConflict(owner))return;
        if(!isVaultLockedError(error))toast(error.message,true);
    }finally{passcode="";}
}

// After the server refused a key change (409): load its wrapped key. Returns true when this device's key
// was replaced, in which case the vault is now locked and must be opened with the current passphrase.
async function adoptServerKeyAfterConflict(owner){
    try{
        const fresh=await api("/api/v1/lock");
        if(!await LockstepVault.synchronizeWrappedKey(owner,fresh.wrappedKey,fresh.vaultRevision))return false;
        state.lockConfig=normalizeLockConfig(fresh);localStorage.setItem(`authsync.lock.${owner}`,JSON.stringify(state.lockConfig));
        clearUnlockedSession();closeVaultSurfaces();showLocked();
        return true;
    }catch{return false;}
}

function confirmAction({title,message,label="Continue",iconName="shield",danger=false,passphrase=false}) {
    const dialog=el("confirm-dialog"); el("confirm-title").textContent=title; el("confirm-message").textContent=message; el("confirm-accept").textContent=label;
    el("confirm-icon-use").setAttribute("href",`#i-${iconName}`); dialog.classList.toggle("danger",danger); dialog.returnValue="cancel";
    const input=el("confirm-passkey"); input.value=""; input.classList.toggle("hidden",!passphrase); state.confirmPasskey="";
    // A newer question replaces one still open: the earlier one counts as cancelled instead of waiting forever.
    const previous=state.confirmationResolve; state.confirmationResolve=null; previous?.(false); state.confirmationAborted=false;
    if(!dialog.open)dialog.showModal(); if(passphrase) input.focus();
    return new Promise((resolve)=>{state.confirmationResolve=resolve;});
}
function resolveConfirmation(){const passkeyInput=el("confirm-passkey"),aborted=Boolean(state.confirmationAborted);state.confirmationAborted=false;state.confirmPasskey=aborted?"":passkeyInput.value;passkeyInput.value="";state.confirmationResolve?.(!aborted&&el("confirm-dialog").returnValue==="confirm");state.confirmationResolve=null;}

// The theme button cycles System -> Light -> Dark. index.html applies the saved choice before the first paint.
function cycleTheme(){const next=THEMES[(THEMES.indexOf(state.theme)+1)%THEMES.length];applyTheme(next);try{if(next==="system")localStorage.removeItem("authsync.theme");else localStorage.setItem("authsync.theme",next);}catch{/* storage unavailable */}toast(`${next[0].toUpperCase()+next.slice(1)} theme`);}
function effectiveTheme(){return state.theme==="system"?(matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light"):state.theme;}
function applyTheme(theme){
    state.theme=THEMES.includes(theme)?theme:"system";
    if(state.theme==="system")delete document.documentElement.dataset.theme;else document.documentElement.dataset.theme=state.theme;
    const next=THEMES[(THEMES.indexOf(state.theme)+1)%THEMES.length];
    el("theme-toggle")?.setAttribute("title",`Theme: ${state.theme}. Switch to ${next}`);
    el("theme-toggle")?.setAttribute("aria-label",`Theme: ${state.theme}. Switch to ${next} theme`);
    const color=effectiveTheme()==="dark"?"#10131a":"#f7f8fb";
    document.querySelectorAll('meta[name="theme-color"]').forEach(meta=>{if(state.theme==="system")meta.setAttribute("content",meta.media?.includes("dark")?"#10131a":"#f7f8fb");else meta.setAttribute("content",color);});
    if(el("google-sign-in")?.dataset.gsiReady)renderGoogleButton();
}
// Google's own button options only (Google's internal class names change without notice). It is drawn
// again when the header switches between the full and the icon-only button, or the theme changes.
function compactHeader(){
    if(!compactHeader.query){
        compactHeader.query=window.matchMedia("(max-width: 420px)");
        compactHeader.query.addEventListener("change",()=>{if(el("google-sign-in")?.dataset.gsiReady)renderGoogleButton();});
    }
    return compactHeader.query.matches;
}
function renderGoogleButton(){
    if(!window.google?.accounts?.id)return;
    const container=el("google-sign-in");
    if(!container)return;
    const compact=compactHeader(),dark=effectiveTheme()==="dark";
    const look=`${compact?"icon":"standard"}-${dark?"dark":"light"}`;
    if(container.dataset.gsiReady===look)return;
    container.dataset.gsiReady=look;
    container.replaceChildren();
    const gsiDiv=document.createElement("div");
    gsiDiv.id="gsi-btn-root";
    container.appendChild(gsiDiv);
    google.accounts.id.renderButton(gsiDiv,{type:compact?"icon":"standard",theme:dark?"filled_black":"outline",size:"large",text:"signin_with",shape:"pill",logo_alignment:"left"});
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
    // Errors stay longer (and can be dismissed by clicking them); progress messages stay until replaced.
    if(!sticky)state.toastTimer=setTimeout(()=>hideToastNode(node),isError?8000:4500);
}
function showInlineError(id,message){el(id).textContent=message;el(id).classList.remove("hidden");}
function hideInlineError(id){el(id).textContent="";el(id).classList.add("hidden");}
// 6 digits: "123 456"; 7: "123 4567"; 8: "1234 5678".
function formatCode(code){if(!code)return "------";if(code.length===6)return `${code.slice(0,3)} ${code.slice(3)}`;if(code.length===7)return `${code.slice(0,3)} ${code.slice(3)}`;if(code.length===8)return `${code.slice(0,4)} ${code.slice(4)}`;return code;}
// Elements are built with the DOM, never from HTML strings, so the page can enforce Trusted Types.
function h(tag, attributes = {}, ...children) {
    const node = document.createElement(tag);
    for (const [name, value] of Object.entries(attributes)) {
        if (value === false || value === null || value === undefined) continue;
        if (name === "className") node.className = value;
        else node.setAttribute(name, value === true ? "" : String(value));
    }
    node.append(...children.filter((child) => child !== null && child !== undefined && child !== false));
    return node;
}
function iconNode(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#i-${name}`);
    svg.append(use);
    return svg;
}
// The token payload is UTF-8 (names such as "José" or "प्रिया"): decode the bytes, not atob's Latin-1 string.
function tokenClaims(token){try{const binary=atob(token.split(".")[1].replace(/-/g,"+").replace(/_/g,"/"));return JSON.parse(new TextDecoder().decode(Uint8Array.from(binary,c=>c.charCodeAt(0))));}catch{return null;}}
function isExpired(token){const claims=tokenClaims(token);return !claims||claims.exp*1000<Date.now()+30000;}

initialize().catch((error)=>{hideLoader();toast(error.message,true);});
