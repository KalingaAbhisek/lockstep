// ---- Passphrase helpers: strength estimate and a random suggestion -------------------------------------
// New or changed passphrases need at least 12 characters. A suggestion is six random words from a
// 256-word list plus a number (about 55 bits of randomness), generated locally with crypto.getRandomValues.
const NEW_PASSPHRASE_MIN_LENGTH = 12;
const reducedMotionPreference = matchMedia("(prefers-reduced-motion: reduce)");
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

const $ = (id) => document.getElementById(id);
const EXPIRING_THRESHOLD_MILLIS = 5_000;
const SESSION_REVOKED_NOTICE_KEY = "sessionRevokedNotice";
let entries = [];
let originalEntries = new Map();
let serverOffsetMillis = 0;
let refreshing = false;
let vaultViewEpoch = 0;
let editing = false;
let draggedId = null;
let themePreference = "system";
let navigating = false;
let pinnedEntryIds = new Set();
let localEntryOrder = [];
let confirmationResolve = null;
let confirmPasskeyValue = "";
let restoreReturnView = "signed-out";
let lockConfig = { enabled: false, timeoutSeconds: 300, lockOnScreenLock:false };
const LOCK_TIMEOUT_LABELS = new Map([
    [300,"5 minutes"],[600,"10 minutes"],[900,"15 minutes"],[1200,"20 minutes"],[1500,"25 minutes"],
    [1800,"30 minutes"],[2100,"35 minutes"],[2400,"40 minutes"],[2700,"45 minutes"],[3000,"50 minutes"],
    [3300,"55 minutes"],[3600,"1 hour"],[7200,"2 hours"],[14400,"4 hours"],[28800,"8 hours"],
    [43200,"12 hours"],[86400,"1 day"],[172800,"2 days"],[604800,"1 week"]
]);
let isAuthenticated = false;
let lockSetupRequired = false;
let userDisplayName = "";
let recoveryFileRead = 0;
// A change from another device that arrived while the list could not be redrawn (edit mode or an open dialog):
// the data is already synchronized, and the list is redrawn as soon as editing ends or the dialog closes.
let liveRedrawPending = false;

function renderConnectivityStatus(online) {
    const indicator=$("connectivity-status");
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

function checkActiveSession() {
    if(isAuthenticated&&navigator.onLine)void send("CHECK_SESSION");
}

// Fail-safe listener binding: one missing element must never abort every handler after it.
function bind(id, ...args) {
    const node = document.getElementById(id);
    if (!node) { console.warn(`Lockstep: #${id} not found in popup.html`); return; }
    node.addEventListener(...args);
}

bind("login", "click", async () => {
    const result = await send("LOGIN");
    if (result.ok) {
        userDisplayName = result.data.displayName || result.data.email || "";
        showRouteSkeleton();
        loadLockAndRoute();
    } else status(result.error, true);
});
function showRouteSkeleton() {
    $("signed-out").classList.add("hidden");
    $("signed-in").classList.add("hidden");
    $("locked").classList.add("hidden");
    $("restore").classList.add("hidden");
    $("initializing").classList.remove("hidden");
    $("normal-tools").classList.add("hidden");
    $("edit-tools").classList.add("hidden");
}
bind("settings", "click", openSettings);
bind("settings-back", "click", hideSettings);
bind("settings-privacy", "click", async () => {
    const result = await send("OPEN_PRIVACY");
    if (!result.ok) settingsMessage(result.error, true);
});
bind("scan", "click", startScan);
async function startScan() {
    const result = await send("START_SCAN");
    if (result.ok) window.close(); else status(result.error, true);
}
bind("edit", "click", () => setEditing(true));
bind("done", "click", saveEdits);
bind("add", "click", openAdd);
bind("empty-add", "click", openAdd);
bind("cancel-add", "click", closeAdd);
bind("method-scan", "click", startScan);
bind("method-manual", "click", () => openSubDialog("manual-dialog"));
bind("method-uris", "click", () => openSubDialog("uri-dialog"));
bind("method-images", "click", () => $("qr-image-files").click());
bind("qr-image-files", "change", importQrImages);
bind("manual-form", "submit", addManualEntry);
bind("uri-form", "submit", importOtpUrls);
document.querySelectorAll("[data-close]").forEach((button) => button.addEventListener("click", () => $(button.dataset.close).close()));
bind("settings-lock", "click", openLockSettings);
bind("lock-form", "submit", saveLockSettings);
bindPassphraseHelpers($("lock-form"), $("lock-passcode"), $("lock-confirm"), $("lock-strength"), $("lock-suggest"), $("lock-suggestion"));
bindPassphraseHelpers($("restore-form"), $("restore-passcode"), $("restore-passcode-confirm"), $("restore-strength"), $("restore-suggest"), $("restore-suggestion"));
bind("lock-dialog", "cancel", event => { if (lockSetupRequired) event.preventDefault(); });
bind("unlock-form", "submit", unlockAuthenticator);
bind("lock-now", "click", lockAuthenticator);
bind("close-qr", "click", () => $("qr-dialog").close());
bind("qr-dialog", "close", clearQrDialog);
bind("confirm-cancel", "click", () => $("confirm-dialog").close("cancel"));
bind("confirm-accept", "click", () => $("confirm-dialog").close("confirm"));
// Enter in the passphrase field confirms, like submitting a form.
bind("confirm-passkey", "keydown", (event) => { if (event.key === "Enter" && !event.isComposing) { event.preventDefault(); if (confirmWordMatches()) $("confirm-dialog").close("confirm"); } });
bind("confirm-passkey", "input", () => { if (confirmWord) $("confirm-accept").disabled = !confirmWordMatches(); });
bind("confirm-dialog", "close", () => {
    const typed = confirmWordMatches();
    confirmPasskeyValue = confirmWord ? "" : $("confirm-passkey").value; $("confirm-passkey").value = "";
    confirmWord = null; configureConfirmInput(null);
    confirmationResolve?.(typed && $("confirm-dialog").returnValue === "confirm");
    confirmationResolve = null;
});
document.querySelectorAll("[data-settings-detail]").forEach((button) => {
    button.setAttribute("aria-expanded", "false");
    button.addEventListener("click", () => toggleSettingsDetail(button));
});
document.querySelectorAll("[data-theme-value]").forEach((button) => {
    button.addEventListener("click", () => setTheme(button.dataset.themeValue));
});
bind("settings-sync", "click", async () => {
    const button = $("settings-sync");
    await chrome.storage.session.set({ lastUnlockedAt: Date.now() });
    button.disabled = true;
    try {
        const loaded = await withProgress("Synchronizing…", () => load(true));
        if (!loaded || $("locked").classList.contains("hidden") === false) return;
        await chrome.storage.session.set({ lastUnlockedAt: Date.now() });
        settingsMessage(`${entries.length} account${entries.length === 1 ? "" : "s"} synchronized.`);
    } finally {
        button.disabled = false;
    }
});
bind("settings-export", "click", exportBackup);
bind("settings-import", "click", () => $("backup-file").click());
bind("backup-file", "change", importBackup);
// Files are checked before reading: backups allow 1,000 accounts / 8 MiB; recovery files allow 16 KiB.
const MAX_BACKUP_FILE_BYTES = 8 * 1024 * 1024;
const MAX_RECOVERY_KEY_FILE_BYTES = 16 * 1024;
bind("restore-key-file-button", "click", () => $("restore-key-file").click());
bind("restore-key-file", "change", loadRecoveryKeyFile);
async function loadRecoveryKeyFile(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    const epoch=vaultViewEpoch,read=++recoveryFileRead;
    const current=()=>epoch===vaultViewEpoch&&read===recoveryFileRead&&!$("restore").classList.contains("hidden");
    try {
        if (file.size > MAX_RECOVERY_KEY_FILE_BYTES) throw new Error("This file is too large to be a Lockstep recovery key.");
        const match = (await file.text()).match(/LS2-M-[A-Za-z0-9_-]{43}/);
        if(!current())return;
        if (!match) throw new Error("The selected file does not contain a valid Lockstep recovery key.");
        $("restore-key").value = match[0];
        $("restore-file-name").textContent = file.name;
        $("restore-file-name").classList.remove("hidden");
        $("restore-error").textContent = "";
    } catch (error) { if(current())$("restore-error").textContent = error.message; }
}
bind("settings-recovery-export", "click", async () => {
    const passcode = await confirmExportPassphrase("Download recovery key?",
        `Anyone with the recovery key can restore and decrypt your vault. Enter your passphrase to continue. ${DOWNLOADS_WARNING}`, "Download", "lock");
    if (passcode === null) return;
    const result = await send("EXPORT_RECOVERY_KEY", { passcode });
    if (!result.ok) { if (handleSessionProblem(result)) return; settingsMessage(result.error, true); return; }
    downloadRecoveryKeyFile(result.data);
    settingsMessage("Recovery key downloaded. Store it somewhere private.");
});
function downloadRecoveryKeyFile(value) {
    const text = `Lockstep recovery key\n\n${value}\n\nKeep this file private. Anyone with this key can restore and decrypt your authenticator vault.\n`;
    const blobUrl = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
    const download = document.createElement("a");
    download.href = blobUrl;
    download.download = `lockstep-recovery-key-${new Date().toISOString().slice(0, 10)}.txt`;
    download.click();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}
bind("settings-key-rotate", "click", async () => {
    const confirmed = await confirmAction({ title: "Rotate recovery key?", message: "A brand-new recovery key is generated and every account is re-encrypted with it. The new recovery key will be downloaded; your old recovery key stops working. Other devices lock when they detect this change and use the new key after unlocking with your current passphrase. Enter your passphrase to continue.", confirmLabel: "Rotate recovery key", iconName: "lock", passphrase: true });
    const passcode = confirmPasskeyValue; confirmPasskeyValue = "";
    if (!confirmed) return;
    if (passcode.length < 4) { settingsMessage("Enter your passphrase to rotate the recovery key.", true); return; }
    const result = await withProgress("Rotating recovery key…", () => send("ROTATE_ENCRYPTION_KEY", { passcode }));
    if (!result.ok) { if (handleSessionProblem(result)) return; settingsMessage(result.error, true); return; }
    downloadRecoveryKeyFile(result.data.recoveryKey);
    await load(true);
    if (result.data.synchronized) settingsMessage(`Recovery key rotated to version ${result.data.version} and downloaded; store it somewhere private.`);
    else settingsMessage(`Recovery key rotated on this device (version ${result.data.version}) and downloaded, but syncing failed: ${result.data.syncError} Unlock again to retry.`, true);
});
async function signOutAndRemoveData() {
    const stored=await chrome.storage.local.get(["vaultSubject","appSessionId"]);
    const authentication={owner:stored.vaultSubject,session:stored.appSessionId};
    const confirmed = await confirmAction({ title:"Sign out?", confirmLabel:"Sign out", iconName:"trash", tone:"danger",
        message:"This browser's encrypted copy of your vault is deleted and you are signed out. Your synchronized accounts stay on the server and on your other devices. Any accounts or changes that have not uploaded will be permanently lost." });
    if(!confirmed)return;
    const result=await send("LOGOUT", {authentication});
    if(!result.ok){status("Could not remove this browser's vault data. Please try signing out again.",true);return;}
    await hideSettings();
    showSignedOut();
    status("Signed out. This browser's copy of the vault was removed.");
}
bind("settings-signout", "click", signOutAndRemoveData);
// Ends every Lockstep session of the account (all browsers and this extension). Needs the server, so it
// reports an error and keeps this device signed in when offline.
bind("settings-signout-all", "click", async () => {
    const confirmed = await confirmAction({ title: "Sign out of all devices?", message: "Every browser and extension signed in to your Lockstep account is signed out. Each one needs a Google sign-in again; your accounts stay saved.", confirmLabel: "Sign out everywhere", iconName: "signout" });
    if (!confirmed) return;
    const result = await send("LOGOUT_ALL");
    if (!result.ok) { settingsMessage(`Could not sign out of all devices: ${result.error}`, true); return; }
    await hideSettings();
    showSignedOut();
    status("Signed out of all devices");
});

bind("entries", "input", (event) => {
    const card = event.target.closest(".entry");
    const entry = entries.find((item) => item.id === card?.dataset.id);
    if (!entry) return;
    if (event.target.dataset.field === "issuer") entry.issuer = event.target.value;
    if (event.target.dataset.field === "accountName") entry.accountName = event.target.value;
});

bind("entries", "click", async (event) => {
    const actionButton = event.target.closest("[data-action]");
    const card = event.target.closest(".entry");
    if (!actionButton || !card) return;
    const entry = entries.find((item) => item.id === card.dataset.id);
    if (!entry) return;
    const action = actionButton.dataset.action;

    if (action === "copy") {
        if (!entry.code) return;
        try {
            let current=entry;
            if(!(entry.validUntilEpochMillis>Date.now()+serverOffsetMillis)) {
                const result=await send("GET_CURRENT_CODE",{id:entry.id});
                if(!result.ok){if(!handleSessionProblem(result))status(result.error,true);return;}
                current=result.data;
            }
            if(!isAuthenticated || !$("locked").classList.contains("hidden") || !(current.validUntilEpochMillis>Date.now()) || !current.code)return;
            await navigator.clipboard.writeText(current.code); status("Code copied");
        }
        catch { status("The code could not be copied. Select it and copy it manually.", true); }
    } else if (action === "qr") {
        await showQr(entry);
    } else if (action === "remove") {
        const confirmed = await confirmAction({
            title: "Remove account?",
            message: `Enter your Lockstep passphrase to remove ${entry.issuer} (${entry.accountName}) from every synchronized device.`,
            confirmLabel: "Remove",
            iconName: "minus",
            tone: "danger", passphrase: true
        });
        const passcode = confirmPasskeyValue; confirmPasskeyValue = "";
        if (!confirmed) return;
        const result = await send("DELETE_ENTRY", { id: entry.id, passcode });
        if (!result.ok) { if (!handleSessionProblem(result)) status(result.error, true); return; }
        entries = entries.filter((item) => item.id !== entry.id);
        await saveLocalOrder();
        originalEntries.delete(entry.id);
        renderEntries();
        status("Account removed");
    } else if (action === "pin") {
        syncDraftsFromInputs();
        await toggleLocalPin(entry.id);
    } else if (action === "quick-pin") {
        await toggleLocalPin(entry.id);
    } else if (action === "rescue") {
        const confirmed = await confirmAction({ title: "Open with your previous passphrase", confirmLabel: "Open", iconName: "lock", passphrase: true,
            message: "This account was added on this device while offline, before your recovery key was rotated, and your passphrase has changed since. Enter the passphrase you used then; the account is re-encrypted with your current key and uploaded." });
        const previous = confirmPasskeyValue; confirmPasskeyValue = "";
        if (!confirmed || !previous) return;
        const result = await send("RESCUE_STRANDED", { passcode: previous });
        if (!result.ok) { if (!handleSessionProblem(result)) status(result.error, true); return; }
        await load(true);
        status(result.data ? `${result.data} account${result.data === 1 ? "" : "s"} re-encrypted with your current key.` : "That passphrase does not open this account.", !result.data);
    } else if (action === "retry-upload") {
        const result = await send("RETRY_LOCAL_ONLY", { id: entry.id });
        if (!result.ok) { if (!handleSessionProblem(result)) status(result.error, true); return; }
        await load(true);
    }
});

bind("entries", "dragstart", (event) => {
    const handle = event.target.closest(".drag-handle");
    const card = handle?.closest(".entry");
    if (!editing || !card) { event.preventDefault(); return; }
    syncDraftsFromInputs();
    draggedId = card.dataset.id;
    card.classList.add("dragging");
    event.dataTransfer.effectAllowed = "move";
    event.dataTransfer.setData("text/plain", draggedId);
});

bind("entries", "dragover", (event) => {
    if (!draggedId) return;
    const card = event.target.closest(".entry");
    if (!card || card.dataset.id === draggedId) return;
    event.preventDefault();
    document.querySelectorAll(".entry.drag-over").forEach((node) => node.classList.remove("drag-over"));
    card.classList.add("drag-over");
});

bind("entries", "drop", (event) => {
    const targetCard = event.target.closest(".entry");
    if (!draggedId || !targetCard || targetCard.dataset.id === draggedId) return;
    event.preventDefault();
    const sourceIndex = entries.findIndex((item) => item.id === draggedId);
    const [moved] = entries.splice(sourceIndex, 1);
    let targetIndex = entries.findIndex((item) => item.id === targetCard.dataset.id);
    if (event.clientY > targetCard.getBoundingClientRect().top + targetCard.offsetHeight / 2) targetIndex++;
    entries.splice(targetIndex, 0, moved);
    clearDragState();
    renderEntries();
});

bind("entries", "dragend", clearDragState);

async function showSignedIn(loadVault = true, alreadyResumed = false) {
    const epoch = vaultViewEpoch;
    $("restore").classList.add("hidden");
    $("settings").classList.remove("hidden");
    $("settings-back").classList.add("hidden");
    setAuthenticated(true);
    $("signed-out").classList.add("hidden");
    $("locked").classList.add("hidden");
    $("welcome-message").textContent = userDisplayName ? `Welcome, ${userDisplayName}` : "Welcome";

    if (!loadVault) {
        $("initializing").classList.add("hidden");
        $("signed-in").classList.remove("hidden");
        $("normal-tools").classList.add("hidden");
        $("edit-tools").classList.add("hidden");
        $("lock-now").classList.add("hidden");
        animateView($("signed-in"), "forward");
        return;
    }

    if(!alreadyResumed){
        const resumed=await send("RESUME_VAULT");
        if (epoch !== vaultViewEpoch) return;
        if(!resumed.ok){if(handleSessionProblem(resumed))return;status(resumed.error,true);return;}
        if(!resumed.data){showLocked();return;}
    }

    // Try cache first — render instantly, then refresh in background
    const cached = await send("GET_CACHED_ENTRIES");
    if (epoch !== vaultViewEpoch) return;
    if (!cached.ok && handleSessionProblem(cached)) return;
    if (cached.ok && cached.data) {
        $("initializing").classList.add("hidden");
        entries = cached.data.map((entry) => ({ ...entry, pinned: pinnedEntryIds.has(entry.id) }));
        sortEntriesByLocalPins();
        $("empty").classList.toggle("hidden", entries.length > 0);
        renderEntries();
        $("signed-in").classList.remove("hidden");
        $("normal-tools").classList.toggle("hidden", editing);
        $("edit-tools").classList.toggle("hidden", !editing);
        $("lock-now").classList.toggle("hidden", !lockConfig.enabled);
        animateView($("signed-in"), "forward");
        load(true); // silent background refresh
        return;
    }

    // No cache — show loader until data arrives
    $("signed-in").classList.add("hidden");
    $("initializing").classList.remove("hidden");
    if (!await load(true)) return;
    if (epoch !== vaultViewEpoch) return;
    $("initializing").classList.add("hidden");
    $("signed-in").classList.remove("hidden");
    $("normal-tools").classList.toggle("hidden", editing);
    $("edit-tools").classList.toggle("hidden", !editing);
    $("lock-now").classList.toggle("hidden", !lockConfig.enabled);
    animateView($("signed-in"), "forward");
}

function clearVaultView() {
    document.body?.classList.remove("editing");
    vaultViewEpoch++;
    refreshing = false;
    localRefreshing = false;
    entries = [];
    originalEntries.clear();
    draggedId = null;
    editing = false;
    $("entries").replaceChildren();
    clearTimeout(syncFollowTimer);
    syncFollowTimer = null;
}

function showSignedOut() {
    clearVaultView();
    status("");
    document.querySelectorAll("dialog[open]").forEach((dialog) => dialog.close("cancel"));
    $("restore-form").reset(); $("restore-file-name").classList.add("hidden"); $("unlock-passcode").value = "";
    $("settings-view").classList.add("hidden");
    $("auth-view").classList.remove("hidden");
    $("settings").classList.remove("hidden");
    $("settings-back").classList.add("hidden");
    $("restore").classList.add("hidden");
    setAuthenticated(false);
    editing = false;
    $("initializing").classList.add("hidden");
    $("signed-out").classList.remove("hidden");
    $("signed-in").classList.add("hidden");
    $("locked").classList.add("hidden");
    $("lock-now").classList.add("hidden");
    $("normal-tools").classList.add("hidden");
    $("edit-tools").classList.add("hidden");
    animateView($("signed-out"), "back");
}

function showLocked() {
    clearVaultView();
    const entering = $("locked").classList.contains("hidden") || $("auth-view").classList.contains("hidden");
    document.querySelectorAll("dialog[open]").forEach((dialog)=>dialog.close("cancel"));
    toast("");
    status("");
    $("settings-view").classList.add("hidden");
    $("auth-view").classList.remove("hidden");
    $("settings").classList.remove("hidden");
    $("settings-back").classList.add("hidden");
    $("restore").classList.add("hidden");
    setAuthenticated(true);
    entries = [];
    $("entries").replaceChildren();
    $("empty").classList.add("hidden");
    $("initializing").classList.add("hidden");
    $("signed-out").classList.add("hidden");
    $("signed-in").classList.add("hidden");
    $("locked").classList.remove("hidden");
    $("lock-now").classList.add("hidden");
    $("normal-tools").classList.add("hidden");
    $("edit-tools").classList.add("hidden");
    $("unlock-passcode").value = "";
    $("unlock-error").textContent = "";
    $("restore-form").reset(); $("restore-file-name").classList.add("hidden");
    if (entering) {
        animateView($("locked"), "forward");
        $("unlock-passcode").focus();
    }
}

async function showSettings() {
    if (navigating) return;
    const epoch = vaultViewEpoch;
    $("normal-tools").classList.add("hidden");
    $("edit-tools").classList.add("hidden");
    animateTitle("Settings");
    settingsMessage("");
    const locked = !$("locked").classList.contains("hidden");
    for (const id of ["settings-lock", "settings-export", "settings-import", "settings-recovery-export", "settings-key-rotate", "settings-sync"]) {
        $(id).classList.toggle("hidden", locked);
    }
    await transitionViews($("auth-view"), $("settings-view"), "forward");
    if (epoch !== vaultViewEpoch) return;
    $("settings").classList.add("hidden");
    $("settings-back").classList.remove("hidden");
}

function setAuthenticated(authenticated) {
    isAuthenticated = authenticated;
    document.querySelectorAll(".authenticated-setting").forEach((element) => {
        element.classList.toggle("hidden", !authenticated);
    });
}

async function openSettings() {
    const button = $("settings");
    if (!$("restore").classList.contains("hidden") || button.classList.contains("spinning") || navigating) return;
    const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (!reducedMotion) button.classList.add("spinning");
    try {
        await showSettings();
    } finally {
        button.classList.remove("spinning");
    }
}

async function hideSettings() {
    if (navigating) return;
    const epoch = vaultViewEpoch;
    animateTitle("Lockstep");
    await transitionViews($("settings-view"), $("auth-view"), "back");
    if (epoch !== vaultViewEpoch) return;
    $("settings").classList.remove("hidden");
    $("settings-back").classList.add("hidden");
    const locked = !$("locked").classList.contains("hidden");
    $("normal-tools").classList.toggle("hidden", !isAuthenticated || editing || locked);
    $("edit-tools").classList.toggle("hidden", !isAuthenticated || !editing || locked);
}

async function transitionViews(from, to, direction) {
    if (navigating) return;
    const epoch = vaultViewEpoch;
    navigating = true;
    const main = document.querySelector("main");
    const reducedMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
    to.classList.remove("hidden");

    if (reducedMotion) {
        from.classList.add("hidden");
        navigating = false;
        return;
    }

    const outgoingX = direction === "forward" ? "-22px" : "22px";
    const incomingX = direction === "forward" ? "22px" : "-22px";
    const timing = {
        duration: 300,
        easing: "cubic-bezier(.22,.72,.18,1)",
        fill: "both"
    };
    let outgoing;
    let incoming;

    main.classList.add("navigating");
    try {
        outgoing = from.animate([
            { opacity: 1, transform: "translateX(0)" },
            { opacity: 0, transform: `translateX(${outgoingX})` }
        ], timing);
        incoming = to.animate([
            { opacity: 0, transform: `translateX(${incomingX})` },
            { opacity: 1, transform: "translateX(0)" }
        ], timing);
        await Promise.allSettled([outgoing.finished, incoming.finished]);
        if (epoch !== vaultViewEpoch) return;
        from.classList.add("hidden");
    } finally {
        outgoing?.cancel();
        incoming?.cancel();
        main.classList.remove("navigating");
        navigating = false;
    }
}

function animateView(element, direction) {
    const animationClass = direction === "back" ? "view-enter-back" : "view-enter-forward";
    element.classList.remove("view-enter-forward", "view-enter-back");
    void element.offsetWidth;
    element.classList.add(animationClass);
    setTimeout(() => element.classList.remove(animationClass), 280);
}

function animateTitle(title) {
    const heading = $("view-title");
    heading.textContent = title;
    heading.classList.remove("title-changing");
    void heading.offsetWidth;
    heading.classList.add("title-changing");
    setTimeout(() => heading.classList.remove("title-changing"), 240);
}

function toggleSettingsDetail(button) {
    const detail = $(button.dataset.settingsDetail);
    const opening = detail.classList.contains("hidden");
    button.classList.toggle("expanded", opening);
    button.setAttribute("aria-expanded", String(opening));
    detail.classList.toggle("hidden", !opening);
    if (opening) {
        detail.classList.remove("detail-reveal");
        void detail.offsetWidth;
        detail.classList.add("detail-reveal");
        setTimeout(() => detail.classList.remove("detail-reveal"), 220);
    }
}

async function loadTheme() {
    const stored = await chrome.storage.local.get("themePreference");
    applyTheme(["system", "light", "dark"].includes(stored.themePreference) ? stored.themePreference : "system");
}

async function loadLocalPins() {
    const stored = await chrome.storage.local.get(["pinnedEntryIds", "entryOrder"]);
    pinnedEntryIds = new Set(Array.isArray(stored.pinnedEntryIds) ? stored.pinnedEntryIds : []);
    localEntryOrder = Array.isArray(stored.entryOrder) ? stored.entryOrder : [];
}

async function setTheme(theme) {
    const animate = !matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (animate) document.body.classList.add("theme-transitioning");
    applyTheme(theme);
    await chrome.storage.local.set({ themePreference: theme });
    settingsMessage(`${theme[0].toUpperCase() + theme.slice(1)} theme`);
    if (animate) setTimeout(() => document.body.classList.remove("theme-transitioning"), 260);
}

function applyTheme(theme) {
    themePreference = theme;
    if (theme === "system") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.dataset.theme = theme;
    document.querySelectorAll("[data-theme-value]").forEach((button) => {
        const selected = button.dataset.themeValue === themePreference;
        button.classList.toggle("active", selected);
        button.setAttribute("aria-pressed", String(selected));
    });
}

async function load(force = false) {
    if (refreshing || editing && !force) return false;
    const epoch = vaultViewEpoch;
    refreshing = true;
    liveRedrawPending = false;
    const hasSkeleton = $("entries").querySelector(".entry-skel") !== null;
    const requestStartedAt = Date.now();
    const result = await send("LIST_ENTRIES");
    if (epoch !== vaultViewEpoch) return false;
    if (!result.ok) {
        refreshing = false;
        if (handleSessionProblem(result)) return false; // e.g. service worker restarted and dropped the in-memory key
        if (hasSkeleton) $("entries").replaceChildren();
        status(result.error, true);
        return false;
    }
    const currentLock = await send("GET_LOCK_CONFIG");
    if (epoch !== vaultViewEpoch) return false;
    if (currentLock.ok) { lockConfig = currentLock.data; updateLockSummary(); }
    await lockIfWorkerLocked();
    if (epoch !== vaultViewEpoch) { refreshing = false; return false; }
    entries = result.data.map((entry) => ({ ...entry, pinned: pinnedEntryIds.has(entry.id) }));
    sortEntriesByLocalPins();
    const responseReceivedAt = Date.now();
    // Taken from an account that has a code: one that cannot be opened has no generation time, and using it
    // would turn every countdown into "NaNs" and stop codes from refreshing on time.
    const timed = entries.find((entry) => Number.isFinite(entry.serverEpochMillis));
    const offset = timed ? timed.serverEpochMillis - ((requestStartedAt + responseReceivedAt) / 2) : 0;
    serverOffsetMillis = Number.isFinite(offset) ? offset : 0;
    $("empty").classList.toggle("hidden", entries.length > 0);
    renderEntries();
    refreshing = false;
    await showSyncState();
    return true;
}

// "Synchronizing · N changes pending" is checked again every 2 seconds while changes are waiting, so the
// banner clears once they are uploaded (for at most a minute; the regular refresh takes over after that).
let syncFollowTimer = null, listRetryTimer = null;
async function showSyncState(followUntil = Date.now() + 60000) {
    const epoch = vaultViewEpoch;
    clearTimeout(syncFollowTimer); syncFollowTimer = null;
    const syncState = await send("GET_SYNC_STATE");
    if (epoch !== vaultViewEpoch) return;
    if (syncState.ok && syncState.data.notice) toast(syncState.data.notice, true); // a refused change was dropped
    if (syncState.ok && (!syncState.data.online || syncState.data.pending)) {
        status(`${syncState.data.online ? "Synchronizing" : "Offline"}${syncState.data.pending ? ` · ${syncState.data.pending} change${syncState.data.pending === 1 ? "" : "s"} pending` : ""}`);
        if (syncState.data.online && Date.now() < followUntil) syncFollowTimer = setTimeout(() => showSyncState(followUntil), 2000);
    } else status("");
    // The list could not be downloaded for a temporary reason: try again in 5 to 10 seconds while the popup is open.
    clearTimeout(listRetryTimer); listRetryTimer = null;
    if (syncState.ok && syncState.data.online && Number.isFinite(syncState.data.retryInMillis)) {
        listRetryTimer = setTimeout(() => { listRetryTimer = null; if (epoch === vaultViewEpoch && isAuthenticated && !$("signed-in").classList.contains("hidden")) load(true); },
            Math.max(1000, syncState.data.retryInMillis));
    }
}

function renderEntries() {
    // Built as elements, not HTML text: account names can never become markup (Trusted Types enforced).
    $("entries").replaceChildren(...entries.map((entry) => {
        const pinLabel = entry.pinned ? "Unpin" : "Pin";
        const broken = Boolean(entry.error);
        return h("article", { className: broken ? "entry broken" : "entry", "data-id": entry.id },
            h("div", { className: "view-fields" },
                h("p", { className: "issuer", title: entry.issuer }, entry.issuer),
                entry.localOnly ? h("p", { className: "local-only-label", title: "The server refused this account, so it exists only in this browser." }, "Only on this device") : null,
                h("div", { className: "code-row" },
                    broken
                        ? h("p", { className: "entry-error", role: "note" }, entry.error)
                        : h("button", { className: "code", "data-action": "copy", title: "Copy code", "aria-label": `Copy code ${entry.code} for ${entry.issuer}` }, formatCode(entry.code)),
                    entry.pinned ? h("span", { className: "pin-indicator", title: "Pinned" }, iconNode("pin", "inline-pin")) : null),
                h("p", { className: "account", title: entry.accountName }, entry.accountName)),
            h("div", { className: "entry-actions" },
                entry.canRetry ? h("button", { className: "entry-action", "data-action": "retry-upload", title: "Upload again", "aria-label": "Upload this account again" }, iconNode("refresh")) : null,
                entry.needsOldPassphrase ? h("button", { className: "entry-action", "data-action": "rescue", title: "Open with your previous passphrase", "aria-label": "Open with your previous passphrase" }, iconNode("lock")) : null,
                h("button", { className: "entry-action qr-action", "data-action": "qr", title: "Show QR code", "aria-label": "Show QR code", disabled: broken }, iconNode("qr")),
                h("button", { className: entry.pinned ? "entry-action pin-button pin-indicator active" : "entry-action pin-button", "data-action": "quick-pin", title: pinLabel, "aria-label": pinLabel }, iconNode("pin"))),
            h("div", { className: "edit-fields" },
                h("button", { className: "remove", "data-action": "remove", title: "Remove account", "aria-label": "Remove account" }, iconNode("minus")),
                h("input", { className: "edit-input", "data-field": "issuer", maxlength: "128", value: entry.issuer, "aria-label": "Issuer" }),
                h("button", { className: entry.pinned ? "pin-edit active" : "pin-edit", "data-action": "pin", title: pinLabel, "aria-label": pinLabel }, iconNode("pin")),
                h("input", { className: "edit-input", "data-field": "accountName", maxlength: "256", value: entry.accountName, "aria-label": "Account name" }),
                h("button", { className: "drag-handle", draggable: "true", title: "Drag to reorder", "aria-label": "Drag to reorder" }, iconNode("grip"))),
            h("span", { className: "countdown" }), h("span", { className: "progress" }));
    }));
    tick();
}

function sortEntriesByLocalPins() {
    const ranks = new Map(localEntryOrder.map((id, index) => [id, index]));
    entries.sort((left, right) => Number(right.pinned) - Number(left.pinned)
        || (ranks.get(left.id) ?? Number.MAX_SAFE_INTEGER) - (ranks.get(right.id) ?? Number.MAX_SAFE_INTEGER)
        || (left.createdAtEpochMillis ?? 0) - (right.createdAtEpochMillis ?? 0));
    localEntryOrder = entries.map((entry) => entry.id);
}

async function saveLocalOrder() {
    localEntryOrder = entries.map((entry) => entry.id);
    await chrome.storage.local.set({ entryOrder: localEntryOrder });
}

async function toggleLocalPin(entryId) {
    const entry = entries.find((item) => item.id === entryId);
    if (!entry) return;
    const previousPositions = captureEntryPositions();
    const card = document.querySelector(`.entry[data-id="${CSS.escape(entryId)}"]`);
    card?.classList.add("pinning");
    entry.pinned = !entry.pinned;
    if (entry.pinned) pinnedEntryIds.add(entryId);
    else pinnedEntryIds.delete(entryId);
    await chrome.storage.local.set({ pinnedEntryIds: [...pinnedEntryIds] });
    sortEntriesByLocalPins();
    await saveLocalOrder();
    renderEntries();
    animateEntryReorder(previousPositions, entryId);
}

function captureEntryPositions() {
    return new Map([...document.querySelectorAll(".entry")].map((node) => [
        node.dataset.id,
        node.getBoundingClientRect()
    ]));
}

function animateEntryReorder(previousPositions, highlightedId) {
    if (matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    document.querySelectorAll(".entry").forEach((node) => {
        const previous = previousPositions.get(node.dataset.id);
        if (!previous) return;
        const current = node.getBoundingClientRect();
        const deltaX = previous.left - current.left;
        const deltaY = previous.top - current.top;
        const highlighted = node.dataset.id === highlightedId;
        if (Math.abs(deltaX) < 1 && Math.abs(deltaY) < 1) {
            if (highlighted) {
                node.animate([
                    { transform: "scale(1)" },
                    { transform: "scale(1.018)", offset: .55 },
                    { transform: "scale(1)" }
                ], { duration: 300, easing: "ease-out" });
            }
            return;
        }

        node.animate([
            { transform: `translate(${deltaX}px, ${deltaY}px) scale(1)`, zIndex: highlighted ? 2 : 1 },
            { transform: "translate(0, 0) scale(1)", zIndex: highlighted ? 2 : 1, offset: .82 },
            { transform: highlighted ? "translate(0, 0) scale(1.015)" : "translate(0, 0) scale(1)", zIndex: highlighted ? 2 : 1, offset: .92 },
            { transform: "translate(0, 0) scale(1)", zIndex: 1 }
        ], {
            duration: highlighted ? 440 : 360,
            easing: "cubic-bezier(.22,.72,.18,1)"
        });
    });
}

// The 100 ms countdown looks entries up by ID and only rewrites the seconds label when it changes.
let tickIndex = { entries: null, length: -1, byId: new Map() };
function entryForTick(id) {
    if (tickIndex.entries !== entries || tickIndex.length !== entries.length) {
        tickIndex = { entries, length: entries.length, byId: new Map(entries.map((item) => [item.id, item])) };
    }
    return tickIndex.byId.get(id) || entries.find((item) => item.id === id);
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
    const serverNowMillis = Date.now() + serverOffsetMillis;
    let hasExpiredCode = false;
    const progress = [];
    document.querySelectorAll(".entry").forEach((node) => {
        const entry = entryForTick(node.dataset.id);
        if (!entry || !Number.isFinite(entry.validUntilEpochMillis)) return; // an account that could not be opened has no code
        const remainingMillis = Math.max(0, entry.validUntilEpochMillis - serverNowMillis);
        node.classList.toggle("expiring", remainingMillis > 0 && remainingMillis <= EXPIRING_THRESHOLD_MILLIS);
        const countdown = node.querySelector(".countdown"), label = `${Math.ceil(remainingMillis / 1000)}s`;
        if (countdown.textContent !== label) countdown.textContent = label;
        animateProgress(node.querySelector(".progress"), entry, remainingMillis, progress);
        if (remainingMillis === 0) hasExpiredCode = true;
    });
    if (progress.length) {
        // Commit every starting width in one layout, rather than forcing a layout for every account.
        void $("entries").offsetWidth;
        for (const { bar, remaining } of progress) {
            bar.style.transition = `transform ${remaining}ms linear`;
            bar.style.transform = "scaleX(0)";
        }
    }
    if (hasExpiredCode && !refreshing && !editing) refreshLocalCodes();
}

// When only the codes changed (same accounts, same order), the cards are updated in place instead of being
// rebuilt, so keyboard focus and hover survive a code change.
function updateCodesInPlace(next) {
    const cards = [...$("entries").querySelectorAll(".entry")];
    if (cards.length !== next.length || cards.some((card, index) => card.dataset.id !== next[index].id || card.classList.contains("entry-skel"))) return false;
    const current = new Map(entries.map((entry) => [entry.id, entry]));
    if (next.some((entry, index) => Boolean(entry.error) !== cards[index].classList.contains("broken")
        || entry.issuer !== current.get(entry.id)?.issuer || entry.accountName !== current.get(entry.id)?.accountName
        || entry.pinned !== current.get(entry.id)?.pinned || Boolean(entry.localOnly) !== Boolean(current.get(entry.id)?.localOnly)
        || Boolean(entry.canRetry) !== Boolean(current.get(entry.id)?.canRetry)
        || Boolean(entry.needsOldPassphrase) !== Boolean(current.get(entry.id)?.needsOldPassphrase)
        || entry.error !== current.get(entry.id)?.error)) return false;
    entries = next;
    cards.forEach((card, index) => {
        const entry = next[index], code = card.querySelector(".code");
        if (!code || entry.error) return;
        const text = formatCode(entry.code);
        if (code.textContent !== text) code.textContent = text;
        code.setAttribute("aria-label", `Copy code ${entry.code} for ${entry.issuer}`);
    });
    tick();
    return true;
}

// Codes are generated locally, so a new 30-second code needs no server request.
// The background refresh (every 30 seconds while visible, and on return) keeps shared changes current.
let localRefreshing = false;
async function refreshLocalCodes() {
    if (refreshing || editing || localRefreshing) return;
    const epoch = vaultViewEpoch;
    localRefreshing = true;
    try {
        const result = await send("GET_CACHED_ENTRIES");
        if (epoch !== vaultViewEpoch) return;
        if (!result.ok) { if (!handleSessionProblem(result)) load(); return; }
        if (refreshing || editing) return;
        const previous = entries;
        entries = result.data.map((entry) => ({ ...entry, pinned: pinnedEntryIds.has(entry.id) }));
        sortEntriesByLocalPins();
        const next = entries;
        entries = previous;
        if (updateCodesInPlace(next)) return;
        entries = next;
        $("empty").classList.toggle("hidden", entries.length > 0);
        renderEntries();
    } finally {
        if (epoch === vaultViewEpoch) localRefreshing = false;
    }
}

// QR libraries are only needed to scan an image or show a QR code, so they load after the popup opens.
const VENDOR_SCRIPTS = { jsQR: "vendor/jsQR.js", QRCode: "vendor/qrcode.js" };
const vendorLoads = new Map();
// Trusted Types (enforced by the manifest): the only script URLs the popup loads are its vendor files.
const scriptUrlPolicy = globalThis.trustedTypes?.createPolicy?.("lockstep-scripts", {
    createScriptURL(url) {
        if (!Object.values(VENDOR_SCRIPTS).includes(url)) throw new TypeError(`Script URL not allowed: ${url}`);
        return url;
    }
});
const trustedScriptUrl = (url) => scriptUrlPolicy ? scriptUrlPolicy.createScriptURL(url) : url;
function loadVendorScript(name) {
    if (globalThis[name]) return Promise.resolve();
    if (vendorLoads.has(name)) return vendorLoads.get(name);
    const pending = new Promise((resolve, reject) => {
        const script = document.createElement("script");
        script.src = trustedScriptUrl(VENDOR_SCRIPTS[name]);
        script.async = true;
        script.onload = () => resolve();
        script.onerror = () => { vendorLoads.delete(name); script.remove(); reject(new Error(`${name} could not be loaded.`)); };
        document.head.append(script);
    });
    vendorLoads.set(name, pending);
    return pending;
}

// Each opening of the QR dialog gets its own number. A QR code that finishes after the dialog was closed,
// reopened for another account, or the vault locked is dropped: it can neither show the wrong account's
// secret nor stay behind in a closed dialog.
let qrRequest = 0;
async function showQr(entry) {
    const request = ++qrRequest, epoch = vaultViewEpoch;
    const current = () => request === qrRequest && epoch === vaultViewEpoch && $("qr-dialog").open && $("locked").classList.contains("hidden");
    $("qr-title").textContent = entry.issuer;
    $("qr-account").textContent = entry.accountName;
    $("qr-loading").textContent = "";
    $("qr-loading").classList.add("hidden");
    $("qr-skeleton").classList.remove("hidden");
    $("qr-image").classList.add("hidden");
    $("qr-image").removeAttribute("src");
    if (!$("qr-dialog").open) $("qr-dialog").showModal();
    const result = await send("GET_ENTRY_QR", { id: entry.id });
    if (!current()) return;
    if (!result.ok) {
        if (handleSessionProblem(result)) return;
        $("qr-skeleton").classList.add("hidden");
        $("qr-loading").textContent = result.error;
        $("qr-loading").classList.remove("hidden");
        return;
    }
    let source;
    try {
        await loadVendorScript("QRCode").catch(() => null);
        source = await QRCode.toDataURL(result.data, { errorCorrectionLevel: "M", margin: 2, width: 320 });
    } catch {
        if (!current()) return;
        $("qr-skeleton").classList.add("hidden");
        $("qr-loading").textContent = "The QR code could not be shown. Reload Lockstep and try again.";
        $("qr-loading").classList.remove("hidden");
        return;
    }
    if (!current()) return;
    $("qr-image").src = source;
    $("qr-skeleton").classList.add("hidden");
    $("qr-image").classList.remove("hidden");
    $("qr-loading").classList.add("hidden");
}

function clearQrDialog() {
    qrRequest++;
    $("qr-skeleton").classList.remove("hidden");
    $("qr-loading").classList.add("hidden");
    $("qr-image").removeAttribute("src");
    $("qr-image").classList.add("hidden");
}

function setEditing(value) {
    editing = value;
    if (value) originalEntries = new Map(entries.map((entry) => [entry.id, { ...entry }]));
    document.body.classList.toggle("editing", value);
    $("normal-tools").classList.toggle("hidden", value);
    $("edit-tools").classList.toggle("hidden", !value);
    renderEntries();
    if (!value) setTimeout(flushLiveRedraw, 0);
}

async function saveEdits() {
    syncDraftsFromInputs();
    if (entries.some((entry) => !entry.issuer.trim() || !entry.accountName.trim())) {
        status("Issuer and account name are required.", true);
        return;
    }
    $("done").disabled = true;
    try {
        for (const entry of entries) {
            const original = originalEntries.get(entry.id);
            if (!original || original.issuer !== entry.issuer.trim() || original.accountName !== entry.accountName.trim()) {
                const result = await send("UPDATE_ENTRY", {
                    id: entry.id,
                    issuer: entry.issuer.trim(),
                    accountName: entry.accountName.trim()
                });
                if (!result.ok) throw new Error(result.error);
            }
        }
        await saveLocalOrder();
        editing = false;
        document.body.classList.remove("editing");
        $("normal-tools").classList.remove("hidden");
        $("edit-tools").classList.add("hidden");
        await load(true);
    } catch (error) {
        status(error.message, true);
    } finally {
        $("done").disabled = false;
    }
}

function syncDraftsFromInputs(event) {
    const card = event?.target?.closest?.(".entry");
    const cards = card ? [card] : document.querySelectorAll(".entry");
    const byId = card ? null : new Map(entries.map(entry => [entry.id, entry]));
    cards.forEach((card) => {
        const entry = byId ? byId.get(card.dataset.id) : entryForTick(card.dataset.id);
        if (!entry) return;
        const issuer = card.querySelector('[data-field="issuer"]');
        const accountName = card.querySelector('[data-field="accountName"]');
        if (issuer) entry.issuer = issuer.value;
        if (accountName) entry.accountName = accountName.value;
    });
}

function clearDragState() {
    draggedId = null;
    document.querySelectorAll(".entry.dragging,.entry.drag-over").forEach((node) => node.classList.remove("dragging", "drag-over"));
}

async function confirmRecentGoogleSignIn(type, extra) {
    const reasons = {
        ROTATE_ENCRYPTION_KEY: "rotate your recovery key",
        SET_LOCK_CONFIG: "change your passphrase",
        RESET_VAULT: "reset your vault",
        DELETE_ENTRY: "remove this account",
        LOGOUT_ALL: "sign out of all devices",
        IMPORT_RECOVERY_KEY: "restore your vault",
        UPGRADE_PROTECTION: "strengthen your vault protection"
    };
    const dialog = $("reauth-dialog");
    $("reauth-message").textContent = `Confirm with Google to ${reasons[type] || "continue"}.`;
    dialog.returnValue = "cancel";
    const confirmed = await new Promise(resolve => {
        dialog.addEventListener("close", () => resolve(dialog.returnValue === "confirm"), { once: true });
        dialog.showModal();
    });
    if (!confirmed) return { ok: false, code: "REAUTH_CANCELLED", error: "Google confirmation was cancelled. Nothing was changed." };
    return chrome.runtime.sendMessage({ ...extra, type: "CONFIRM_RECENT_GOOGLE_SIGN_IN", action: type });
}

async function send(type, extra = {}) {
    const epoch = vaultViewEpoch;
    const changed = () => ({ ok: false, code: "VIEW_CHANGED", error: "The vault view changed. Try again." });
    const endingSession = ["LOGOUT","LOGOUT_ALL","RESET_VAULT"].includes(type);
    if (endingSession) {
        liveSessionEndRequests++;
        liveChanges?.stop(); liveChanges = null; liveChangesIdentity = "";
    }
    try {
        let response = await chrome.runtime.sendMessage({ type, ...extra });
        if (epoch !== vaultViewEpoch) return changed();
        const protectedActions = ["ROTATE_ENCRYPTION_KEY", "SET_LOCK_CONFIG", "RESET_VAULT", "DELETE_ENTRY", "LOGOUT_ALL", "IMPORT_RECOVERY_KEY", "UPGRADE_PROTECTION"];
        if (response?.code === "REAUTH_REQUIRED" && !response.ok && protectedActions.includes(type)) {
            // The worker confirms with Google and retries once, even if Chrome closes this popup.
            response = await confirmRecentGoogleSignIn(type, extra);
            if (epoch !== vaultViewEpoch) return changed();
        }
        if (response && typeof response.ok === "boolean") {
            if(!response.ok&&response.code==="VAULT_LOCKED")showLocked();
            if(!response.ok&&(response.code==="SESSION_REVOKED"||response.code==="SESSION_EXPIRED")){
                await chrome.storage.local.remove(SESSION_REVOKED_NOTICE_KEY);
                if (epoch !== vaultViewEpoch) return changed();
                isAuthenticated=false;
                showSignedOut();
                status(response.error||(response.code==="SESSION_EXPIRED"?"Your 30-day Lockstep session has expired. Sign in with Google again.":"This Lockstep session was replaced by a login on another device."),true);
            }
            return response;
        }
        return {
            ok: false,
            error: "The extension background service is unavailable. Reload Lockstep from chrome://extensions and try again."
        };
    } catch (error) {
        if (epoch !== vaultViewEpoch) return changed();
        return {
            ok: false,
            error: error?.message || "The extension background service is unavailable. Reload Lockstep from chrome://extensions and try again."
        };
    } finally { if (endingSession) liveSessionEndRequests--; }
}
let toastTimer = null;
let statusTimer = null;
let settingsMessageTimer = null;
function toast(message, isError = false, sticky = false) {
    let node = $("toast");
    if (!node) { node = document.createElement("div"); node.id = "toast"; node.setAttribute("role", "status"); node.setAttribute("aria-live", "polite"); document.body.appendChild(node); }
    clearTimeout(toastTimer);
    if (!message) { node.classList.remove("show"); return; }
    node.textContent = message;
    node.classList.toggle("error", isError);
    node.classList.add("show");
    if (!sticky) toastTimer = setTimeout(() => node.classList.remove("show"), isError ? 6000 : 3500);
}
function status(message, isError = false) {
    clearTimeout(statusTimer);
    if (isError && /^Vault is locked|^Vault locked|^Unlock the authenticator/.test(message || "")) {
        showLocked();
        $("unlock-error").textContent = message;
        return;
    }
    $("status").textContent = message || ""; $("status").classList.toggle("error", isError);
    if (message && isError) statusTimer = setTimeout(() => status(""), 6000);
}
function settingsMessage(message, isError = false) {
    clearTimeout(settingsMessageTimer);
    if (isError && /^Vault is locked|^Vault locked|^Unlock the authenticator/.test(message || "")) {
        showLocked();
        $("unlock-error").textContent = message;
        return;
    }
    $("settings-message").textContent = message || ""; $("settings-message").classList.toggle("error", isError);
    if (message && isError) settingsMessageTimer = setTimeout(() => settingsMessage(""), 6000);
    if (message && !isError) toast(message);
}
// Shows a sticky "working" toast while a slow action runs, then lets the caller's result message replace it.
async function withProgress(message, action) {
    toast(message, false, true);
    try { return await action(); } finally { if ($("toast")?.textContent === message) toast(""); }
}
function openAdd() { $("add-dialog").showModal(); }
function closeAdd() { $("add-dialog").close(); }
function openSubDialog(id) { $("add-dialog").close(); $(id).showModal(); }

async function addManualEntry(event) {
    event.preventDefault();
    const issuer = $("manual-issuer").value.trim();
    const account = $("manual-account").value.trim() || nextDefaultAccountName(entries);
    const secret = $("manual-secret").value.toUpperCase().replace(/[\s-]/g, "");
    const period = Number($("manual-period").value);
    if (!/^[A-Z2-7]+=*$/.test(secret)) { $("manual-error").textContent = "The secret key can only contain the letters A-Z and the digits 2-7."; return; }
    const parameters = new URLSearchParams({ secret, issuer, algorithm: $("manual-algorithm").value, digits: $("manual-digits").value, period: String(period) });
    const otpAuthUri = `otpauth://totp/${encodeURIComponent(`${issuer}:${account}`)}?${parameters}`;
    const result = await send("ADD_OTP_URI", { otpAuthUri });
    if (!result.ok) { $("manual-error").textContent = result.error; return; }
    $("manual-form").reset(); $("manual-period").value = "30"; $("manual-error").textContent = ""; $("manual-dialog").close();
    await load(true); status("Account added");
}

async function importOtpUrls(event) {
    event.preventDefault();
    try {
        const otpAuthUris = parseBackup($("otp-uris").value);
        const result = await send("IMPORT_ENTRIES", { otpAuthUris });
        if (!result.ok) throw new Error(result.error);
        $("uri-form").reset(); $("uri-dialog").close(); await load(true);
        status(result.data.failed ? `${result.data.imported} imported; ${result.data.failed} failed.` : `${result.data.imported} account${result.data.imported === 1 ? "" : "s"} imported.`, result.data.failed > 0);
    } catch (error) { $("uri-error").textContent = error.message; }
}

async function importQrImages(event) {
    const files = [...(event.target.files || [])]; event.target.value = ""; if (!files.length) return;
    const epoch = vaultViewEpoch;
    await loadVendorScript("jsQR").catch(() => null);
    if (epoch !== vaultViewEpoch) return;
    const otpAuthUris = [];
    let firstError="";
    for (const file of files) {
        if (epoch !== vaultViewEpoch) return;
        let loaded;
        try {
            loaded=await LockstepImages.load(file);
            if (epoch !== vaultViewEpoch) return;
            const uri=detectQrImage(loaded.source);if(uri)otpAuthUris.push(uri);
        } catch(error){firstError ||= error.message;}
        finally{loaded?.close();}
        await new Promise(requestAnimationFrame);
        if (epoch !== vaultViewEpoch) return;
    }
    if (!otpAuthUris.length) { status(firstError||"No TOTP QR code was found in the selected images.", true); return; }
    const result = await send("IMPORT_ENTRIES", { otpAuthUris });
    if (epoch !== vaultViewEpoch) return;
    if (!result.ok) { status(result.error, true); return; }
    $("add-dialog").close(); await load(true);
    if (epoch !== vaultViewEpoch) return;
    const unreadable = files.length - otpAuthUris.length;
    status(`${result.data.imported} imported${unreadable ? `; ${unreadable} image${unreadable === 1 ? "" : "s"} unreadable` : ""}.`, unreadable > 0 || result.data.failed > 0);
}

function detectQrImage(image) {
    if (typeof window.jsQR !== "function") throw new Error("The QR scanner could not be loaded. Reload Lockstep and try again.");
    const scale=Math.min(1,1600/Math.max(image.width,image.height));
    const canvas = document.createElement("canvas"); canvas.width = Math.max(1,Math.round(image.width*scale)); canvas.height = Math.max(1,Math.round(image.height*scale));
    const context = canvas.getContext("2d", { willReadFrequently: true }); context.drawImage(image, 0, 0,canvas.width,canvas.height);
    const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
    const decoded = window.jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: "attemptBoth" });
    return decoded?.data?.startsWith("otpauth://totp/") ? decoded.data : null;
}

function showRestore(message, returnView) {
    clearVaultView();
    restoreReturnView = returnView || (!$("locked").classList.contains("hidden") ? "locked" : "signed-out");
    animateTitle("Lockstep");
    $("settings-view").classList.add("hidden");
    $("auth-view").classList.remove("hidden");
    $("settings").classList.add("hidden");
    $("settings-back").classList.add("hidden");
    setAuthenticated(true);
    ["initializing", "signed-out", "signed-in", "locked", "normal-tools", "edit-tools", "lock-now"].forEach((id) => $(id).classList.add("hidden"));
    $("restore").classList.remove("hidden");
    $("restore-error").textContent = "";
    if (message) $("restore-message").textContent = message;
    animateView($("restore"), "forward");
    $("restore-key").focus();
}

// Set when the user presses Lock here: a request that was already running then reports "vault locked",
// which is expected and must not show up as an error on the lock screen.
let lockedByUser = false;
function handleSessionProblem(result) {
    // Returns true when the result was a key/session problem that has been routed to the right screen.
    if (result.ok) return false;
    if (result.code === "VIEW_CHANGED" || result.code === "SESSION_CHANGED") return true;
    if (result.code === "KEY_MISSING" || result.code === "NEEDS_RECOVERY") { showRestore(result.error); return true; }
    if (result.code === "SESSION_EXPIRED") { showSignedOut(); status("Session expired. Sign in with Google again.", true); return true; }
    if (result.code === "VAULT_LOCKED" || /^Vault is locked|^Vault locked|^Unlock the authenticator/.test(result.error || "")) {
        showLocked();
        if (!lockedByUser) $("unlock-error").textContent = result.error || "The vault locked automatically. Enter your passphrase to continue.";
        return true;
    }
    return false;
}

// Opening the popup: when this device holds the protected vault, show the saved codes (or the lock screen)
// straight away. The server check (GET_VAULT_STATE) runs alongside; a deleted account still signs out, and
// a key changed on another device locks the vault on the next sync.
async function openFromDevice(remoteState) {
    const epoch = vaultViewEpoch;
    const local = await send("GET_LOCAL_STATE");
    if (epoch !== vaultViewEpoch) return false;
    if (!local.ok || !local.data.usable) return false;
    let { unlocked, lockConfig: localLock } = local.data;
    if (unlocked && navigator.onLine) {
        // While the popup is closed the worker has no live connection, so a key rotation, passphrase change or
        // sign-in elsewhere may not be known yet. Codes appear only after the startup check already running
        // has answered (it locks or signs out the worker if needed); a slow server delays them at most 1.5 s,
        // and offline the device's vault opens at once.
        const answered = await Promise.race([remoteState.then(() => true, () => true), new Promise(resolve => setTimeout(() => resolve(false), 1500))]);
        if (epoch !== vaultViewEpoch) return false;
        if (answered) {
            const remote = await remoteState.catch(() => null);
            if (!remote?.ok || !remote.data.hasSubject) return false; // routed (signed out, with its notice) by loadLockAndRoute
            const current = await send("GET_LOCAL_STATE");
            if (epoch !== vaultViewEpoch || !current.ok || !current.data.usable) return false;
            ({ unlocked, lockConfig: localLock } = current.data);
        }
    }
    userDisplayName = local.data.displayName || "";
    lockConfig = localLock;
    updateLockSummary();
    if (unlocked) await showSignedIn(true, true); else showLocked(); // GET_LOCAL_STATE already resumed it
    const routedEpoch = vaultViewEpoch;
    remoteState.then((state) => {
        if (routedEpoch === vaultViewEpoch) return applyRemoteState(state);
    }).catch(() => null);
    return true;
}
// A refused or expired session, or a deleted account, means "sign in again"; anything else (a server that is busy or
// briefly unreachable, a sign-in change still in progress) does not.
function needsSignIn(result) {
    return !result.ok && ["SESSION_REVOKED", "SESSION_EXPIRED", "ACCOUNT_MISSING"].includes(result.code);
}
// The startup check and a lock-settings read take a changed key from the server and lock the worker without
// reporting an error (they are reads, not vault operations). If codes are on screen and the worker is now
// locked, the lock screen replaces them.
async function lockIfWorkerLocked() {
    if ($("signed-in").classList.contains("hidden")) return;
    const epoch = vaultViewEpoch;
    const local = await send("GET_LOCAL_STATE");
    if (epoch !== vaultViewEpoch || !local.ok || !local.data.usable || local.data.unlocked) return;
    showLocked();
    $("unlock-error").textContent = "Your passphrase or recovery key changed on another device. Enter your current passphrase to continue.";
}
async function applyRemoteState(state) {
    // The screen was already chosen from this device's vault; a temporary failure of the check leaves it.
    if (!state.ok) { if (needsSignIn(state)) showSignedOut(); return; }
    if (!state.data.hasSubject) { showSignedOut(); return; }
    await lockIfWorkerLocked();
    const { accountExists, newAccountSetupAuthorized, keyState, displayName } = state.data;
    if (displayName) userDisplayName = displayName;
    if (accountExists === false && !newAccountSetupAuthorized) {
        showSignedOut(); status("Your server account no longer exists. Sign in again to start fresh.", true); return;
    }
    if (keyState === "none") await loadLockAndRoute(Promise.resolve(state));
}

// When the server could not be asked (not a sign-in problem), the screen follows this device's vault: locked (or
// open, within the lock timeout) when it holds one, otherwise sign-in. The reason is shown; checks resume on
// their own (the 5-10 s retries, live updates).
async function routeFromDevice(failure, epoch, attempt) {
    if (failure.code === "SESSION_CHANGED" || failure.code === "VIEW_CHANGED") {
        if (attempt < 3) setTimeout(() => { if (epoch === vaultViewEpoch) void loadLockAndRoute(null, attempt + 1); }, 400);
        return;
    }
    if (needsSignIn(failure)) { showSignedOut(); if (failure.error) status(failure.error, true); return; }
    const local = await send("GET_LOCAL_STATE");
    if (epoch !== vaultViewEpoch) return;
    if (local.ok && local.data.usable) {
        lockConfig = local.data.lockConfig; updateLockSummary();
        if (local.data.unlocked) await showSignedIn(true, true); else showLocked();
    } else showSignedOut();
    if (failure.error) status(failure.error, true);
}
async function loadLockAndRoute(statePromise = null, attempt = 0) {
    const epoch = vaultViewEpoch;
    const state = await (statePromise || send("GET_VAULT_STATE"));
    if (epoch !== vaultViewEpoch) return;
    if (!state.ok) { await routeFromDevice(state, epoch, attempt); return; }
    if (!state.data.hasSubject) { showSignedOut(); return; }
    const { accountExists, newAccountSetupAuthorized, keyState, displayName } = state.data;
    userDisplayName = displayName || "";
    if (accountExists === false && !newAccountSetupAuthorized) {
        showSignedOut(); status("Your server account no longer exists. Sign in again to start fresh.", true); return;
    }
    const result = await send("GET_LOCK_CONFIG");
    if (epoch !== vaultViewEpoch) return;
    if (!result.ok) { await routeFromDevice(result, epoch, attempt); return; }
    lockConfig = result.data;
    updateLockSummary();
    if (keyState === "none") {
        if (newAccountSetupAuthorized) {
            await showSignedIn(false);
            if (epoch !== vaultViewEpoch) return;
            await openLockSettings({ required: true, refresh: false });
            return;
        }
        // Recovery is determined by the durable vault state, not by a temporary
        // chrome.storage.session flag that can disappear after a background reload.
        showRestore(undefined, "signed-out");
        return;
    }
    // A key exists locally => the lock is enabled (local key is authoritative and works offline).
    lockConfig = { ...lockConfig, enabled: true };
    const resumed = await send("RESUME_VAULT");
    if (epoch !== vaultViewEpoch) return;
    if (resumed.ok && resumed.data) { await showSignedIn(); return; }
    showLocked();
}

bind("restore-form", "submit", async (event) => {
    event.preventDefault();
    const passcode = $("restore-passcode").value;
    if (passcode.length < NEW_PASSPHRASE_MIN_LENGTH) { $("restore-error").textContent = `Passphrase must contain at least ${NEW_PASSPHRASE_MIN_LENGTH} characters.`; return; }
    if (passcode !== $("restore-passcode-confirm").value) { $("restore-error").textContent = "Passphrases do not match."; return; }
    // Restoring is how a locked vault is opened without its passphrase, so the worker must not require it unlocked.
    const result = await send("IMPORT_RECOVERY_KEY", { recoveryKey: $("restore-key").value, passcode, recoveryMode: true });
    if (!result.ok) {
        if (result.code === "SESSION_EXPIRED") { showSignedOut(); status("Session expired. Sign in with Google again.", true); return; }
        $("restore-error").textContent = result.error; return;
    }
    $("restore-form").reset();
    lockConfig = { ...lockConfig, enabled: true };
    await chrome.storage.session.set({ lastUnlockedAt: Date.now() });
    showSignedIn();
});
bind("forgot-passkey", "click", () => showRestore("Enter your recovery key and choose a new passphrase for this device. Without a recovery key, the vault can only be opened with the old passphrase.", "locked"));
bind("restore-back", "click", () => restoreReturnView === "locked" ? showLocked() : showSignedOut());
bind("restore-reset", "click", async () => {
    const confirmed = await confirmAction({
        title: "Reset vault?",
        message: "This permanently deletes all authenticator accounts and vault data from this device and the server. Other devices are signed out and remove their copy when they next sign in. This cannot be undone. Type RESET, then confirm with Google.",
        confirmLabel: "Delete and reset", iconName: "minus", tone: "danger", typedWord: "RESET"
    });
    confirmPasskeyValue = "";
    if (!confirmed) return;
    // No passphrase: this is for someone who lost both the passphrase and every recovery key.
    const result = await send("RESET_VAULT", { confirmation: "RESET" });
    if (!result.ok) {
        if (result.code === "SESSION_EXPIRED") { showSignedOut(); status("Session expired. Sign in with Google again.", true); return; }
        $("restore-error").textContent = result.error; return;
    }
    entries = [];
    showSignedOut();
    status("Vault reset. Sign in again to create lock protection.");
});
bind("restore-signout", "click", signOutAndRemoveData);

async function unlockAuthenticator(event) {
    event.preventDefault();
    let passcode = $("unlock-passcode").value;
    const result = await send("VERIFY_LOCK", { passcode });
    if (!result.ok && handleSessionProblem(result)) return;
    if (!result.ok || !result.data.unlocked) { $("unlock-error").textContent = result.ok ? "Incorrect passphrase." : result.error; return; }
    lockedByUser = false;
    await chrome.storage.session.set({ lastUnlockedAt: Date.now() });
    if (result.data.replaced) {
        // The server's vault was replaced while this device kept an older one with accounts the server lacks.
        const replace = await confirmAction({ title: "Use the server's vault?", confirmLabel: "Use server's vault", iconName: "lock", tone: "danger",
            message: `${result.data.replaced} Use the server's vault to replace this device's copy (export a backup first if you still need those accounts), or cancel to keep it for now.` });
        if (replace) {
            const adopted = await send("ADOPT_SERVER_VAULT", { passcode });
            if (!adopted.ok || !adopted.data.unlocked) {
                showLocked();
                $("unlock-error").textContent = adopted.ok ? "Incorrect passphrase." : (adopted.code === "WRONG_PASSKEY" ? "This device now uses the server's vault. Enter its passphrase." : adopted.error);
                return;
            }
        } else {
            showSignedIn();
            toast("This device kept its older vault. Export what you need, then lock and unlock again to switch to the server's vault.", true, true);
            return;
        }
    }
    await showSignedIn();
    if (result.data.rescued) toast(`${result.data.rescued} account${result.data.rescued === 1 ? "" : "s"} added offline ${result.data.rescued === 1 ? "was" : "were"} re-encrypted with your new recovery key.`);
    if (result.data.upgradeAvailable && !(await chrome.storage.session.get("upgradeOffered")).upgradeOffered) {
        await chrome.storage.session.set({ upgradeOffered: true });
        const accepted = await confirmAction({ title: "Strengthen vault protection?", confirmLabel: "Upgrade", iconName: "shield",
            message: "Your passphrase protects the vault key with an older method. Lockstep can switch it to Argon2id, which makes your passphrase much harder to guess if the encrypted vault is ever stolen. Your passphrase stays the same. You'll be asked to confirm with Google." });
        if (accepted) {
            const upgraded = await send("UPGRADE_PROTECTION", { passcode });
            if (upgraded.ok && upgraded.data?.upgraded) toast("Vault protection upgraded to Argon2id");
            else if (!upgraded.ok && !handleSessionProblem(upgraded) && upgraded.code !== "REAUTH_CANCELLED") toast(upgraded.error, true);
        }
    }
    passcode = "";
}

async function lockAuthenticator() { lockedByUser = true; await send("LOCK_VAULT"); await chrome.storage.session.remove("lastUnlockedAt"); showLocked(); }

async function openLockSettings({ required = false, refresh = true } = {}) {
    if (refresh) {
        const result = await send("GET_LOCK_CONFIG");
        if (!result.ok) { settingsMessage("Sign in with Google before changing lock protection.", true); return; }
        lockConfig = result.data;
    }
    lockSetupRequired = required;
    updateLockSummary();
    $("lock-form").reset(); $("lock-timeout").value = String(lockConfig.timeoutSeconds || 300); $("lock-on-screen-lock").checked=Boolean(lockConfig.lockOnScreenLock); $("lock-error").textContent = "";
    $("lock-dialog-title").textContent = required ? "Create lock protection" : "Change lock protection";
    $("lock-dialog-description").textContent = required
        ? "Create a passphrase before adding or viewing authenticator accounts. When setup finishes, your recovery-key file downloads automatically."
        : "Choose a new passphrase for this device and your synchronized vault.";
    $("lock-dialog-close").classList.toggle("hidden", required);
    $("lock-dialog").showModal();
    $("lock-passcode").focus();
}

async function saveLockSettings(event) {
    event.preventDefault();
    const initialSetup = lockSetupRequired;
    const passcode = $("lock-passcode").value;
    if (passcode.length < NEW_PASSPHRASE_MIN_LENGTH) { $("lock-error").textContent = `Passphrase must contain at least ${NEW_PASSPHRASE_MIN_LENGTH} characters.`; return; }
    if (passcode !== $("lock-confirm").value) { $("lock-error").textContent = "Passphrases do not match."; return; }
    const result = await send("SET_LOCK_CONFIG", { passcode, timeoutSeconds: Number($("lock-timeout").value), lockOnScreenLock:$("lock-on-screen-lock").checked, initialSetup: lockSetupRequired });
    if (!result.ok) {
        if (result.code === "SESSION_EXPIRED" || result.code === "KEY_MISSING") {
            lockSetupRequired = false; $("lock-dialog").close();
            handleSessionProblem(result); return;
        }
        $("lock-error").textContent = result.error; return;
    }
    const recoveryKey = initialSetup ? result.data.recoveryKey : null;
    const savedConfig = { ...result.data };
    delete savedConfig.recoveryKey;
    lockConfig = savedConfig; await chrome.storage.session.set({ lastUnlockedAt: Date.now() }); updateLockSummary();
    lockSetupRequired = false;
    $("lock-dialog").close(); $("lock-now").classList.remove("hidden");
    if (recoveryKey) { downloadRecoveryKeyFile(recoveryKey); settingsMessage("Profile setup complete. Recovery key downloaded; store it somewhere private."); }
    else settingsMessage("Lock protection saved");
    await showSignedIn();
}

function updateLockSummary() {
    const duration=LOCK_TIMEOUT_LABELS.get(Number(lockConfig.timeoutSeconds))||"inactivity";
    $("lock-summary").textContent = lockConfig.enabled ? `Locks after ${duration}${lockConfig.lockOnScreenLock?" or when the screen locks":""}` : "Protect codes with a passphrase";
}
// Exports confirm the vault passphrase first (the worker checks it on this device), so someone at an
// unlocked, unattended browser cannot walk away with every secret. Returns the passphrase, or null.
const DOWNLOADS_WARNING = "Downloads folders are often synced to cloud storage, so keep the file somewhere private.";
async function confirmExportPassphrase(title, message, confirmLabel, iconName) {
    const confirmed = await confirmAction({ title, message, confirmLabel, iconName, passphrase: true });
    const passcode = confirmPasskeyValue; confirmPasskeyValue = "";
    if (!confirmed) return null;
    const check = await send("CHECK_EXPORT_PASSPHRASE", { passcode });
    if (check.ok) return passcode;
    if (!handleSessionProblem(check)) settingsMessage(check.error, true);
    return null;
}

// The backup-password dialog. Export: choose a password (or download without one). Import: enter the
// password of an encrypted backup. `accept` runs on submit; an error it throws is shown and the dialog stays open.
function askBackupPassword({ mode, accept }) {
    const dialog = $("backup-dialog"), exporting = mode === "export";
    $("backup-title").textContent = exporting ? "Protect the backup file" : "Encrypted backup";
    $("backup-message").textContent = exporting
        ? `Choose a password of at least 12 characters to encrypt the file. Without one, anyone who opens the file can copy every code. ${DOWNLOADS_WARNING}`
        : "Enter the password this backup was protected with.";
    $("backup-password").value = ""; $("backup-password-confirm").value = ""; $("backup-error").textContent = "";
    $("backup-password").autocomplete = exporting ? "new-password" : "current-password";
    $("backup-password-confirm").classList.toggle("hidden", !exporting);
    $("backup-plain").classList.toggle("hidden", !exporting);
    $("backup-accept").textContent = exporting ? "Encrypt and download" : "Open backup";
    $("backup-accept").disabled = false;
    return new Promise((resolve) => {
        let settled = false, submitting = false;
        const finish = (value) => {
            if (settled) return;
            settled = true;
            dialog.onclose = null; $("backup-form").onsubmit = null; $("backup-cancel").onclick = null; $("backup-plain").onclick = null;
            $("backup-password").value = ""; $("backup-password-confirm").value = "";
            if (dialog.open) dialog.close();
            resolve(value);
        };
        dialog.onclose = () => finish(null);
        $("backup-cancel").onclick = () => finish(null);
        $("backup-plain").onclick = () => finish({ plain: true });
        $("backup-form").onsubmit = async (event) => {
            event.preventDefault(); if (settled || submitting) return; $("backup-error").textContent = "";
            const password = $("backup-password").value;
            if (exporting && password !== $("backup-password-confirm").value) { $("backup-error").textContent = "The passwords do not match."; return; }
            submitting = true; $("backup-accept").disabled = true;
            try { finish(await accept(password)); }
            catch (error) { if (!settled) $("backup-error").textContent = error.message; }
            finally { if (!settled) { submitting = false; $("backup-accept").disabled = false; } }
        };
        dialog.showModal(); $("backup-password").focus();
    });
}

function downloadFile(text, name, type) {
    const blobUrl = URL.createObjectURL(new Blob([text], { type }));
    const download = document.createElement("a");
    download.href = blobUrl;
    download.download = name;
    download.click();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
}

async function exportBackup() {
    const passcode = await confirmExportPassphrase("Export all accounts?",
        `The file contains the secrets needed to generate every code. Enter your passphrase to continue. ${DOWNLOADS_WARNING}`, "Continue", "export");
    if (passcode === null) return;
    const date = new Date().toISOString().slice(0, 10);
    const choice = await askBackupPassword({ mode: "export", accept: async (backupPassword) => {
        if (backupPassword.length < 12) throw new Error("Use at least 12 characters, or choose No password.");
        const result = await send("EXPORT_ENTRIES", { passcode, backupPassword });
        if (!result.ok) throw new Error(result.error);
        return { encrypted: result.data };
    } });
    if (!choice) return;
    let text = choice.encrypted;
    if (!text) {
        const result = await send("EXPORT_ENTRIES", { passcode });
        if (!result.ok) { if (handleSessionProblem(result)) return; settingsMessage(result.error, true); return; }
        text = result.data;
    }
    if (choice.encrypted) downloadFile(text, `lockstep-backup-${date}.json`, "application/json");
    else downloadFile(text, `lockstep-totp-backup-${date}.txt`, "text/plain;charset=utf-8");
    settingsMessage(`${entries.length} account${entries.length === 1 ? "" : "s"} exported${choice.encrypted ? " (encrypted)" : ""}.`);
}
// typedWord: the user must type this word (for example RESET) before the action button works.
let confirmWord = null;
function confirmWordMatches() { return !confirmWord || $("confirm-passkey").value.trim().toUpperCase() === confirmWord; }
function configureConfirmInput(typedWord) {
    const input = $("confirm-passkey");
    input.type = typedWord ? "text" : "password"; input.autocomplete = typedWord ? "off" : "current-password"; input.spellcheck = false;
    input.placeholder = typedWord ? `Type ${typedWord} to confirm` : "Passphrase"; input.setAttribute("aria-label", typedWord ? `Type ${typedWord} to confirm` : "Vault passphrase");
    $("confirm-accept").disabled = Boolean(typedWord);
}
function confirmAction({ title, message, confirmLabel = "Continue", iconName = "shield", tone = "accent", passphrase = false, typedWord = null }) {
    const dialog = $("confirm-dialog");
    confirmWord = typedWord || null; configureConfirmInput(confirmWord); passphrase = passphrase || Boolean(typedWord);
    $("confirm-passkey").value = ""; $("confirm-passkey").classList.toggle("hidden", !passphrase); confirmPasskeyValue = "";
    $("confirm-title").textContent = title;
    $("confirm-message").textContent = message;
    $("confirm-accept").textContent = confirmLabel;
    $("confirm-icon-use").setAttribute("href", `#icon-${iconName}`);
    dialog.classList.toggle("danger", tone === "danger");
    dialog.returnValue = "cancel";
    // A newer question replaces one still open: the earlier one counts as cancelled instead of waiting forever.
    const previous = confirmationResolve; confirmationResolve = null; previous?.(false);
    if (!dialog.open) dialog.showModal();
    if (passphrase) $("confirm-passkey").focus();
    return new Promise((resolve) => { confirmationResolve = resolve; });
}
async function importBackup(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    const epoch = vaultViewEpoch;
    try {
        if (file.size > MAX_BACKUP_FILE_BYTES) throw new Error("This file is too large to be a Lockstep backup (at most 8 MB).");
        let text = await file.text();
        if (epoch !== vaultViewEpoch) return;
        if (isEncryptedBackupText(text)) {
            text = await askBackupPassword({ mode: "import", accept: async (password) => {
                if (epoch !== vaultViewEpoch) throw Object.assign(new Error("The vault view changed. Import stopped."), {code:"VIEW_CHANGED"});
                const result = await send("DECRYPT_BACKUP", { text, password });
                if (epoch !== vaultViewEpoch) throw Object.assign(new Error("The vault view changed. Import stopped."), {code:"VIEW_CHANGED"});
                if (!result.ok) throw new Error(result.error);
                return result.data;
            } });
            if (epoch !== vaultViewEpoch) return;
            if (text === null) return;
        }
        const otpAuthUris = parseBackup(text);
        settingsMessage(`Importing ${otpAuthUris.length} account${otpAuthUris.length === 1 ? "" : "s"}…`);
        const result = await send("IMPORT_ENTRIES", { otpAuthUris });
        if (epoch !== vaultViewEpoch) return;
        if (!result.ok) throw new Error(result.error);
        await load(true);
        if (epoch !== vaultViewEpoch) return;
        const message = result.data.failed
            ? `${result.data.imported} imported; ${result.data.failed} failed.`
            : `${result.data.imported} account${result.data.imported === 1 ? "" : "s"} imported.`;
        settingsMessage(message, result.data.failed > 0);
    } catch (error) {
        if (epoch === vaultViewEpoch) settingsMessage(error.message, true);
    }
}
// Encrypted backups are JSON (see LockstepVault.encryptBackup); the worker decrypts them.
function isEncryptedBackupText(text) {
    if (!text.trimStart().startsWith("{")) return false;
    try { return JSON.parse(text)?.format === "lockstep-encrypted-backup"; } catch { return false; }
}
function parseBackup(text) {
    const otpAuthUris = text.split(/\r?\n/).map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#"));
    if (!otpAuthUris.length) throw new Error("This backup does not contain any TOTP entries.");
    if (otpAuthUris.length > 1000) throw new Error("A backup can contain at most 1000 entries.");
    const invalidLine = otpAuthUris.findIndex((line) => !line.startsWith("otpauth://totp/"));
    if (invalidLine >= 0) throw new Error(`Not an otpauth://totp/ URL: "${otpAuthUris[invalidLine].length>48?otpAuthUris[invalidLine].slice(0,48)+"…":otpAuthUris[invalidLine]}"`);
    return otpAuthUris;
}
function nextDefaultAccountName(items) {
    const highest = items.reduce((maximum, item) => {
        const match = /^Account (\d+)$/.exec(item.accountName || "");
        return match ? Math.max(maximum, Number(match[1])) : maximum;
    }, 0);
    return `Account ${highest + 1}`;
}
// 6 digits: "123 456"; 7: "123 4567"; 8: "1234 5678".
function formatCode(code) {
    if (!code) return "------";
    if (code.length === 6 || code.length === 7) return `${code.slice(0, 3)} ${code.slice(3)}`;
    if (code.length === 8) return `${code.slice(0, 4)} ${code.slice(4)}`;
    return code;
}
// Elements are built with the DOM, never from HTML strings (the popup enforces Trusted Types).
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
function iconNode(name, className = "") {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    if (className) svg.setAttribute("class", className);
    svg.setAttribute("aria-hidden", "true");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#icon-${name}`);
    svg.append(use);
    return svg;
}

async function initializePopup(){
    await Promise.all([
        loadTheme().catch(() => applyTheme("system")),
        loadLocalPins().catch(() => { pinnedEntryIds = new Set(); })
    ]);
    const remoteState = send("GET_VAULT_STATE");
    if (!await openFromDevice(remoteState)) await loadLockAndRoute(remoteState);
    const stored=await chrome.storage.local.get(SESSION_REVOKED_NOTICE_KEY);
    if(stored[SESSION_REVOKED_NOTICE_KEY]){
        await chrome.storage.local.remove(SESSION_REVOKED_NOTICE_KEY);
        if(!isAuthenticated)status(stored[SESSION_REVOKED_NOTICE_KEY],true);
    }
}
// The QR libraries load only when they are used (QR image import, showing a QR code): the popup is rebuilt
// every time it opens, so preloading them would parse about 280 KB on every opening.
void initializePopup();
$("settings-version").textContent = `Lockstep ${chrome.runtime.getManifest().version}`;
// Passphrases, secrets, otpauth URLs and suggested passphrases never stay in a closed form.
[["manual-dialog", "manual-form"], ["uri-dialog", "uri-form"], ["lock-dialog", "lock-form"]].forEach(([dialog, form]) => bind(dialog, "close", () => {
    $(form).reset();
    if (form === "manual-form") $("manual-period").value = "30";
    const error = $(form.replace("-form", "-error")); if (error) error.textContent = "";
}));
renderConnectivityStatus(navigator.onLine);
checkConnectivity();
// The seconds label changes once a second and the progress bar is a CSS transition: 4 checks a second suffice.
setInterval(tick, 250);
// Server checks happen when the popup opens, when it becomes visible again and when the connection
// returns. The interval is only a fallback for a popup that stays open; connectivity is checked locally.
const BACKGROUND_REFRESH_MILLIS = 30000;
let liveChanges = null, liveChangesIdentity = "", reconcilingLiveChanges = false, liveSessionEndRequests = 0;
// See LIVE_SESSION_ENDED in the worker: a still-valid session reconnects; an unreachable server is asked again
// (up to three times, then the session is treated as ended).
async function confirmLiveSessionEnd(authentication, identity, attempt = 0) {
    const result = await send("LIVE_SESSION_ENDED", { authentication, final: attempt >= 3 });
    if (liveChangesIdentity !== identity) return;
    if (result.ok) { liveChanges = null; liveChangesIdentity = ""; return; } // still signed in: reconnect
    if (result.code === "UNCONFIRMED") setTimeout(() => void confirmLiveSessionEnd(authentication, identity, attempt + 1), 5000);
}
async function reconcileLiveChanges() {
    if (reconcilingLiveChanges || liveSessionEndRequests) return;
    reconcilingLiveChanges = true;
    try {
        const response = isAuthenticated ? await send("GET_CHANGE_STREAM_AUTH") : null;
        const config = response?.ok && response.data.enabled ? response.data : null;
        const identity = config ? JSON.stringify(config.authentication) : "";
        if (identity === liveChangesIdentity) return;
        liveChanges?.stop(); liveChanges = null; liveChangesIdentity = identity;
        if (!config) return;
        liveChanges = LockstepLiveChanges.watch({
            connect: signal => fetch(config.url,{headers:config.headers,cache:"no-store",signal}),
            onSession: () => confirmLiveSessionEnd(config.authentication, identity),
            onChange: async () => {
                if (liveChangesIdentity !== identity) throw Object.assign(new Error("Sign-in changed"),{code:"SESSION_CHANGED"});
                let result = await send("LIVE_SYNC",{authentication:config.authentication});
                if (!result.ok && result.code === "VAULT_LOCKED") {
                    handleSessionProblem(result);
                    result = await send("LIVE_SYNC",{authentication:config.authentication});
                }
                if (!result.ok) {
                    if (result.code === "ACCOUNT_MISSING") { showSignedOut(); status(result.error,true); return; }
                    if (handleSessionProblem(result)) return;
                    throw Object.assign(new Error(result.error),{code:result.code,retryAfterMillis:result.retryAfterMillis});
                }
                if (refreshing) throw new Error("Sync in progress");
                const currentLock = await send("GET_LOCK_CONFIG");
                if (currentLock.ok) { lockConfig = currentLock.data; updateLockSummary(); }
                if ($("signed-in").classList.contains("hidden")) return;
                if (!editing && !document.querySelector("dialog[open]")) await load(true);
                else liveRedrawPending = true;
            }
        });
    } finally { reconcilingLiveChanges = false; }
}
function flushLiveRedraw() {
    if (!liveRedrawPending || refreshing || editing || document.querySelector("dialog[open]")
        || $("signed-in").classList.contains("hidden") || !$("locked").classList.contains("hidden")) return;
    void load(true);
}
// Dialog "close" events do not bubble; a capturing listener sees every one. The check runs after the closing
// dialog's own handlers (one dialog may open another, such as Add → Manual entry).
document.addEventListener("close", () => setTimeout(flushLiveRedraw, 0), true);
setInterval(reconcileLiveChanges, 1000);
let remoteLockChecking = false;
async function refreshLockWhileBusy() {
    // Only a vault that has a passphrase can have changed elsewhere. While the passphrase is being created there
    // is nothing to check, and asking would answer "locked" and replace the setup screen with "unlock".
    if (remoteLockChecking || $("signed-in").classList.contains("hidden") || !lockConfig?.enabled) return;
    remoteLockChecking = true;
    try { await send("CHECK_REMOTE_LOCK"); }
    finally { remoteLockChecking = false; }
}
function refreshFromServer() {
    if (document.hidden || !isAuthenticated) return;
    if (editing || document.querySelector("dialog[open]")) {
        void refreshLockWhileBusy();
        return;
    }
    if (!$("signed-in").classList.contains("hidden")) load();
    else checkActiveSession();
}
setInterval(checkConnectivity, 10000);
setInterval(refreshFromServer, BACKGROUND_REFRESH_MILLIS);
document.addEventListener("visibilitychange", refreshFromServer);
window.addEventListener("focus", refreshFromServer);
window.addEventListener("online", () => {
    void send("NETWORK_ONLINE");
    checkConnectivity();
    checkActiveSession();
    if (isAuthenticated && !$("signed-in").classList.contains("hidden")) load(true);
});
window.addEventListener("offline", () => { renderConnectivityStatus(false);if (isAuthenticated) status("Offline"); });

let lastExtensionActivityAt = 0;
function recordExtensionActivity() {
    if (!isAuthenticated || $("signed-in").classList.contains("hidden")) return;
    const now = Date.now();
    if (now - lastExtensionActivityAt < 1000) return;
    lastExtensionActivityAt = now;
    send("TOUCH_VAULT");
}
["pointermove", "pointerdown", "keydown", "touchstart", "scroll"].forEach((eventName) => document.addEventListener(eventName, recordExtensionActivity, { passive: true }));
