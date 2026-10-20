const $ = (id) => document.getElementById(id);
const icon = (name, className = "") => `<svg class="${className}" aria-hidden="true"><use href="#icon-${name}"></use></svg>`;
const EXPIRING_THRESHOLD_MILLIS = 5_000;
let entries = [];
let originalEntries = new Map();
let serverOffsetMillis = 0;
let refreshing = false;
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
bind("lock-dialog", "cancel", event => { if (lockSetupRequired) event.preventDefault(); });
bind("unlock-form", "submit", unlockAuthenticator);
bind("lock-now", "click", lockAuthenticator);
bind("close-qr", "click", () => $("qr-dialog").close());
bind("qr-dialog", "close", clearQrDialog);
bind("confirm-cancel", "click", () => $("confirm-dialog").close("cancel"));
bind("confirm-accept", "click", () => $("confirm-dialog").close("confirm"));
bind("confirm-dialog", "close", () => {
    confirmPasskeyValue = $("confirm-passkey").value; $("confirm-passkey").value = "";
    confirmationResolve?.($("confirm-dialog").returnValue === "confirm");
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
bind("restore-key-file-button", "click", () => $("restore-key-file").click());
bind("restore-key-file", "change", async (event) => {
    const file = event.target.files?.[0];
    if (!file) return;
    try {
        const match = (await file.text()).match(/LS2-M-[A-Za-z0-9_-]{43}/);
        if (!match) throw new Error("The selected file does not contain a valid Lockstep recovery key.");
        $("restore-key").value = match[0];
        $("restore-file-name").textContent = file.name;
        $("restore-file-name").classList.remove("hidden");
        $("restore-error").textContent = "";
    } catch (error) { $("restore-error").textContent = error.message; }
});
bind("settings-recovery-export", "click", async () => {
    const result = await send("EXPORT_RECOVERY_KEY");
    if (!result.ok) { if (handleSessionProblem(result)) return; settingsMessage(result.error, true); return; }
    const text = `Lockstep recovery key\n\n${result.data}\n\nKeep this file private. Anyone with this key can restore and decrypt your authenticator vault.\n`;
    const blobUrl = URL.createObjectURL(new Blob([text], { type: "text/plain;charset=utf-8" }));
    const download = document.createElement("a");
    download.href = blobUrl;
    download.download = `lockstep-recovery-key-${new Date().toISOString().slice(0, 10)}.txt`;
    download.click();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
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
    const confirmed = await confirmAction({ title: "Rotate encryption key?", message: "A brand-new master key is generated and every account is re-encrypted with it. A NEW recovery key will be downloaded; your old recovery key stops working. Other devices pick up the new key the next time they unlock. Enter your passkey to continue.", confirmLabel: "Rotate key", iconName: "lock", passkey: true });
    const passcode = confirmPasskeyValue; confirmPasskeyValue = "";
    if (!confirmed) return;
    if (passcode.length < 4) { settingsMessage("Enter your passkey to rotate the encryption key.", true); return; }
    const result = await withProgress("Rotating encryption key…", () => send("ROTATE_ENCRYPTION_KEY", { passcode }));
    if (!result.ok) { if (handleSessionProblem(result)) return; settingsMessage(result.error, true); return; }
    downloadRecoveryKeyFile(result.data.recoveryKey);
    await load(true);
    if (result.data.synchronized) settingsMessage(`Key rotated to version ${result.data.version}. New recovery key downloaded; store it somewhere private.`);
    else settingsMessage(`Key rotated on this device (version ${result.data.version}) and the new recovery key was downloaded, but syncing failed: ${result.data.syncError} Unlock again to retry.`, true);
});
bind("settings-signout", "click", async () => {
    await send("LOGOUT");
    await hideSettings();
    showSignedOut();
    status("Signed out");
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
        await navigator.clipboard.writeText(entry.code);
        status("Code copied");
    } else if (action === "qr") {
        await showQr(entry);
    } else if (action === "remove") {
        const confirmed = await confirmAction({
            title: "Remove account?",
            message: `${entry.issuer} (${entry.accountName}) will be removed from every synchronized device.`,
            confirmLabel: "Remove",
            iconName: "minus",
            tone: "danger"
        });
        if (!confirmed) return;
        const result = await send("DELETE_ENTRY", { id: entry.id });
        if (!result.ok) { status(result.error, true); return; }
        entries = entries.filter((item) => item.id !== entry.id);
        await saveLocalOrder();
        originalEntries.delete(entry.id);
        renderEntries();
    } else if (action === "pin") {
        syncDraftsFromInputs();
        await toggleLocalPin(entry.id);
    } else if (action === "quick-pin") {
        await toggleLocalPin(entry.id);
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

async function showSignedIn(loadVault = true) {
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

    // Try cache first — render instantly, then refresh in background
    const cached = await send("GET_CACHED_ENTRIES");
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
    $("initializing").classList.add("hidden");
    $("signed-in").classList.remove("hidden");
    $("normal-tools").classList.toggle("hidden", editing);
    $("edit-tools").classList.toggle("hidden", !editing);
    $("lock-now").classList.toggle("hidden", !lockConfig.enabled);
    animateView($("signed-in"), "forward");
}

function showSignedOut() {
    status("");
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
    $("initializing").classList.add("hidden");
    $("signed-out").classList.add("hidden");
    $("signed-in").classList.add("hidden");
    $("locked").classList.remove("hidden");
    $("lock-now").classList.add("hidden");
    $("normal-tools").classList.add("hidden");
    $("edit-tools").classList.add("hidden");
    $("unlock-passcode").value = "";
    $("unlock-error").textContent = "";
    if (entering) {
        animateView($("locked"), "forward");
        $("unlock-passcode").focus();
    }
}

async function showSettings() {
    if (navigating) return;
    $("normal-tools").classList.add("hidden");
    $("edit-tools").classList.add("hidden");
    animateTitle("Settings");
    settingsMessage("");
    const locked = !$("locked").classList.contains("hidden");
    for (const id of ["settings-lock", "settings-export", "settings-import", "settings-recovery-export", "settings-key-rotate", "settings-sync"]) {
        $(id).classList.toggle("hidden", locked);
    }
    await transitionViews($("auth-view"), $("settings-view"), "forward");
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
    animateTitle("Lockstep");
    await transitionViews($("settings-view"), $("auth-view"), "back");
    $("settings").classList.remove("hidden");
    $("settings-back").classList.add("hidden");
    const locked = !$("locked").classList.contains("hidden");
    $("normal-tools").classList.toggle("hidden", !isAuthenticated || editing || locked);
    $("edit-tools").classList.toggle("hidden", !isAuthenticated || !editing || locked);
}

async function transitionViews(from, to, direction) {
    if (navigating) return;
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
    settingsMessage(`${theme[0].toUpperCase() + theme.slice(1)} theme selected.`);
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
    refreshing = true;
    const hasSkeleton = $("entries").querySelector(".entry-skel") !== null;
    const requestStartedAt = Date.now();
    const result = await send("LIST_ENTRIES");
    if (!result.ok) {
        refreshing = false;
        if (handleSessionProblem(result)) return false; // e.g. service worker restarted and dropped the in-memory key
        if (hasSkeleton) $("entries").innerHTML = "";
        status(result.error, true);
        return false;
    }
    entries = result.data.map((entry) => ({ ...entry, pinned: pinnedEntryIds.has(entry.id) }));
    sortEntriesByLocalPins();
    const responseReceivedAt = Date.now();
    if (entries.length) serverOffsetMillis = entries[0].serverEpochMillis - ((requestStartedAt + responseReceivedAt) / 2);
    $("empty").classList.toggle("hidden", entries.length > 0);
    renderEntries();
    refreshing = false;
    const syncState = await send("GET_SYNC_STATE");
    if (syncState.ok && (!syncState.data.online || syncState.data.pending)) {
        status(`${syncState.data.online ? "Synchronizing" : "Offline"}${syncState.data.pending ? ` · ${syncState.data.pending} change${syncState.data.pending === 1 ? "" : "s"} pending` : ""}`);
    } else status("");
    return true;
}

function renderEntries() {
    $("entries").innerHTML = entries.map((entry) => `
        <article class="entry" data-id="${entry.id}">
            <div class="view-fields">
                <p class="issuer">${escapeHtml(entry.issuer)}</p>
                <div class="code-row"><button class="code" data-action="copy" title="Copy code">${formatCode(entry.code)}</button>${entry.pinned ? `<span class="pin-indicator" title="Pinned">${icon("pin", "inline-pin")}</span>` : ''}</div>
                <p class="account">${escapeHtml(entry.accountName)}</p>
            </div>
            <div class="entry-actions">
                <button class="entry-action qr-action" data-action="qr" title="Show QR code" aria-label="Show QR code">${icon("qr")}</button>
                <button class="entry-action pin-button ${entry.pinned ? 'pin-indicator active' : ''}" data-action="quick-pin" title="${entry.pinned ? 'Unpin' : 'Pin'}" aria-label="${entry.pinned ? 'Unpin' : 'Pin'}">${icon("pin")}</button>
            </div>
            <div class="edit-fields">
                <button class="remove" data-action="remove" title="Remove account" aria-label="Remove account">${icon("minus")}</button>
                <input class="edit-input" data-field="issuer" maxlength="128" value="${escapeAttribute(entry.issuer)}" aria-label="Issuer">
                <button class="pin-edit ${entry.pinned ? 'active' : ''}" data-action="pin" title="${entry.pinned ? 'Unpin' : 'Pin'}" aria-label="${entry.pinned ? 'Unpin' : 'Pin'}">${icon("pin")}</button>
                <input class="edit-input" data-field="accountName" maxlength="256" value="${escapeAttribute(entry.accountName)}" aria-label="Account name">
                <button class="drag-handle" draggable="true" title="Drag to reorder" aria-label="Drag to reorder">${icon("grip")}</button>
            </div>
            <span class="countdown"></span><span class="progress"></span>
        </article>`).join("");
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

function tick() {
    const serverNowMillis = Date.now() + serverOffsetMillis;
    let hasExpiredCode = false;
    document.querySelectorAll(".entry").forEach((node) => {
        const entry = entries.find((item) => item.id === node.dataset.id);
        if (!entry) return;
        const remainingMillis = Math.max(0, entry.validUntilEpochMillis - serverNowMillis);
        node.classList.toggle("expiring", remainingMillis > 0 && remainingMillis <= EXPIRING_THRESHOLD_MILLIS);
        node.querySelector(".countdown").textContent = `${Math.ceil(remainingMillis / 1000)}s`;
        node.querySelector(".progress").style.transform = `scaleX(${remainingMillis / (entry.period * 1000)})`;
        if (remainingMillis === 0) hasExpiredCode = true;
    });
    if (hasExpiredCode && !refreshing && !editing) load();
}

async function showQr(entry) {
    $("qr-title").textContent = entry.issuer;
    $("qr-account").textContent = entry.accountName;
    $("qr-loading").textContent = "";
    $("qr-loading").classList.add("hidden");
    $("qr-skeleton").classList.remove("hidden");
    $("qr-image").classList.add("hidden");
    $("qr-dialog").showModal();
    const result = await send("GET_ENTRY_QR", { id: entry.id });
    if (!result.ok) {
        $("qr-skeleton").classList.add("hidden");
        $("qr-loading").textContent = result.error;
        $("qr-loading").classList.remove("hidden");
        return;
    }
    try {
        $("qr-image").src = await QRCode.toDataURL(result.data, { errorCorrectionLevel: "M", margin: 2, width: 320 });
    } catch {
        $("qr-skeleton").classList.add("hidden");
        $("qr-loading").textContent = "The local QR generator is unavailable.";
        $("qr-loading").classList.remove("hidden");
        return;
    }
    $("qr-skeleton").classList.add("hidden");
    $("qr-image").classList.remove("hidden");
    $("qr-loading").classList.add("hidden");
}

function clearQrDialog() {
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
}

async function saveEdits() {
    syncDraftsFromInputs();
    if (entries.some((entry) => !entry.issuer.trim() || !entry.accountName.trim())) {
        status("Issuer and account name cannot be empty.", true);
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

function syncDraftsFromInputs() {
    document.querySelectorAll(".entry").forEach((card) => {
        const entry = entries.find((item) => item.id === card.dataset.id);
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

async function send(type, extra = {}) {
    try {
        const response = await chrome.runtime.sendMessage({ type, ...extra });
        if (response && typeof response.ok === "boolean") {
            if(!response.ok&&response.code==="VAULT_LOCKED")showLocked();
            if(!response.ok&&response.code==="SESSION_REVOKED"){
                isAuthenticated=false;
                showSignedOut();
                status(response.error||"This extension session was replaced by a login on another device.",true);
            }
            return response;
        }
        return {
            ok: false,
            error: "The extension background service is unavailable. Reload Lockstep from chrome://extensions and try again."
        };
    } catch (error) {
        return {
            ok: false,
            error: error?.message || "The extension background service is unavailable. Reload Lockstep and try again."
        };
    }
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
    if (isError && /^Vault is locked|^Unlock the authenticator/.test(message || "")) {
        showLocked();
        $("unlock-error").textContent = message;
        return;
    }
    $("status").textContent = message || ""; $("status").classList.toggle("error", isError);
    if (message && isError) statusTimer = setTimeout(() => status(""), 6000);
}
function settingsMessage(message, isError = false) {
    clearTimeout(settingsMessageTimer);
    if (isError && /^Vault is locked|^Unlock the authenticator/.test(message || "")) {
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
    if (!/^[A-Z2-7]+=*$/.test(secret)) { $("manual-error").textContent = "Secret must be valid Base32 characters (A-Z and 2-7)."; return; }
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
    const otpAuthUris = [];
    for (const file of files) {
        try { const bitmap = await createImageBitmap(file); const uri = detectQrImage(bitmap); bitmap.close(); if (uri) otpAuthUris.push(uri); } catch { /* Counted below. */ }
    }
    if (!otpAuthUris.length) { status("No TOTP QR code was found in the selected images.", true); return; }
    const result = await send("IMPORT_ENTRIES", { otpAuthUris });
    if (!result.ok) { status(result.error, true); return; }
    $("add-dialog").close(); await load(true);
    const unreadable = files.length - otpAuthUris.length;
    status(`${result.data.imported} imported${unreadable ? `; ${unreadable} image${unreadable === 1 ? "" : "s"} unreadable` : ""}.`, unreadable > 0 || result.data.failed > 0);
}

function detectQrImage(image) {
    if (typeof window.jsQR !== "function") throw new Error("QR decoder unavailable");
    const canvas = document.createElement("canvas"); canvas.width = image.width; canvas.height = image.height;
    const context = canvas.getContext("2d", { willReadFrequently: true }); context.drawImage(image, 0, 0);
    const pixels = context.getImageData(0, 0, canvas.width, canvas.height);
    const decoded = window.jsQR(pixels.data, pixels.width, pixels.height, { inversionAttempts: "attemptBoth" });
    return decoded?.data?.startsWith("otpauth://totp/") ? decoded.data : null;
}

function showRestore(message, returnView) {
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

function handleSessionProblem(result) {
    // Returns true when the result was a key/session problem that has been routed to the right screen.
    if (result.ok) return false;
    if (result.code === "KEY_MISSING" || result.code === "NEEDS_RECOVERY") { showRestore(result.error); return true; }
    if (result.code === "SESSION_EXPIRED") { showSignedOut(); status("Session expired. Sign in with Google again.", true); return true; }
    if (result.code === "VAULT_LOCKED" || /^Vault is locked|^Unlock the authenticator/.test(result.error || "")) {
        showLocked();
        $("unlock-error").textContent = result.error || "The vault locked automatically. Enter your passkey to continue.";
        return true;
    }
    return false;
}

async function loadLockAndRoute() {
    const state = await send("GET_VAULT_STATE");
    if (!state.ok || !state.data.hasSubject) { showSignedOut(); return; }
    const { accountExists, newAccountSetupAuthorized, keyState, displayName } = state.data;
    userDisplayName = displayName || "";
    if (accountExists === false && !newAccountSetupAuthorized) {
        showSignedOut(); status("Your server account no longer exists. Sign in again to start fresh.", true); return;
    }
    const result = await send("GET_LOCK_CONFIG");
    if (!result.ok) { showSignedOut(); return; }
    lockConfig = result.data;
    updateLockSummary();
    if (keyState === "none") {
        if (newAccountSetupAuthorized) {
            await showSignedIn(false);
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
    if (resumed.ok && resumed.data) { await showSignedIn(); return; }
    showLocked();
}

bind("restore-form", "submit", async (event) => {
    event.preventDefault();
    const passcode = $("restore-passcode").value;
    if (passcode !== $("restore-passcode-confirm").value) { $("restore-error").textContent = "Passkeys do not match."; return; }
    const result = await send("IMPORT_RECOVERY_KEY", { recoveryKey: $("restore-key").value, passcode });
    if (!result.ok) {
        if (result.code === "SESSION_EXPIRED") { showSignedOut(); status("Session expired. Sign in with Google again.", true); return; }
        $("restore-error").textContent = result.error; return;
    }
    $("restore-form").reset();
    lockConfig = { ...lockConfig, enabled: true };
    await chrome.storage.session.set({ lastUnlockedAt: Date.now() });
    showSignedIn();
});
bind("forgot-passkey", "click", () => showRestore("Enter your recovery key and choose a new passkey for this device. Without a recovery key, the vault can only be opened with the old passkey.", "locked"));
bind("restore-back", "click", () => restoreReturnView === "locked" ? showLocked() : showSignedOut());
bind("restore-reset", "click", async () => {
    const confirmed = await confirmAction({
        title: "Reset vault?",
        message: "This permanently deletes ALL your authenticator accounts from this device and the server. They cannot be recovered without the recovery key.",
        confirmLabel: "Delete and reset", iconName: "minus", tone: "danger"
    });
    if (!confirmed) return;
    const result = await send("RESET_VAULT");
    if (!result.ok) {
        if (result.code === "SESSION_EXPIRED") { showSignedOut(); status("Session expired. Sign in with Google again.", true); return; }
        $("restore-error").textContent = result.error; return;
    }
    entries = [];
    showSignedOut();
    status("Vault reset. Sign in again to create lock protection.");
});
bind("restore-signout", "click", async () => { await send("LOGOUT"); showSignedOut(); });

async function unlockAuthenticator(event) {
    event.preventDefault();
    const result = await send("VERIFY_LOCK", { passcode: $("unlock-passcode").value });
    if (!result.ok && handleSessionProblem(result)) return;
    if (!result.ok || !result.data.unlocked) { $("unlock-error").textContent = result.ok ? "Incorrect passkey." : result.error; return; }
    await chrome.storage.session.set({ lastUnlockedAt: Date.now() });
    showSignedIn();
}

async function lockAuthenticator() { await send("LOCK_VAULT"); await chrome.storage.session.remove("lastUnlockedAt"); showLocked(); }

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
        ? "Create a passkey before adding or viewing authenticator accounts. It cannot be recovered."
        : "Choose a new passkey for this device and your synchronized vault.";
    $("lock-dialog-close").classList.toggle("hidden", required);
    $("lock-dialog").showModal();
    $("lock-passcode").focus();
}

async function saveLockSettings(event) {
    event.preventDefault();
    const passcode = $("lock-passcode").value;
    if (passcode.length < 4) { $("lock-error").textContent = "Passkey must contain at least 4 characters."; return; }
    if (passcode !== $("lock-confirm").value) { $("lock-error").textContent = "Passkeys do not match."; return; }
    const result = await send("SET_LOCK_CONFIG", { passcode, timeoutSeconds: Number($("lock-timeout").value), lockOnScreenLock:$("lock-on-screen-lock").checked, initialSetup: lockSetupRequired });
    if (!result.ok) {
        if (result.code === "SESSION_EXPIRED" || result.code === "KEY_MISSING") {
            lockSetupRequired = false; $("lock-dialog").close();
            handleSessionProblem(result); return;
        }
        $("lock-error").textContent = result.error; return;
    }
    lockConfig = result.data; await chrome.storage.session.set({ lastUnlockedAt: Date.now() }); updateLockSummary();
    lockSetupRequired = false;
    $("lock-dialog").close(); $("lock-now").classList.remove("hidden"); settingsMessage("Lock protection saved.");
    await showSignedIn();
}

function updateLockSummary() {
    const duration=LOCK_TIMEOUT_LABELS.get(Number(lockConfig.timeoutSeconds))||"inactivity";
    $("lock-summary").textContent = lockConfig.enabled ? `Locks after ${duration}${lockConfig.lockOnScreenLock?" or when the screen locks":""}` : "Protect codes with a passkey";
}
async function exportBackup() {
    const confirmed = await confirmAction({
        title: "Export all accounts?",
        message: "The text file contains the secrets needed to generate every code. Store it somewhere private and never share it.",
        confirmLabel: "Export",
        iconName: "export"
    });
    if (!confirmed) return;
    const result = await send("EXPORT_ENTRIES");
    if (!result.ok) { if (handleSessionProblem(result)) return; settingsMessage(result.error, true); return; }
    const blobUrl = URL.createObjectURL(new Blob([result.data], { type: "text/plain;charset=utf-8" }));
    const download = document.createElement("a");
    download.href = blobUrl;
    download.download = `lockstep-totp-backup-${new Date().toISOString().slice(0, 10)}.txt`;
    download.click();
    setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);
    settingsMessage(`${entries.length} account${entries.length === 1 ? "" : "s"} exported.`);
}
function confirmAction({ title, message, confirmLabel = "Continue", iconName = "shield", tone = "accent", passkey = false }) {
    const dialog = $("confirm-dialog");
    $("confirm-passkey").value = ""; $("confirm-passkey").classList.toggle("hidden", !passkey); confirmPasskeyValue = "";
    $("confirm-title").textContent = title;
    $("confirm-message").textContent = message;
    $("confirm-accept").textContent = confirmLabel;
    $("confirm-icon-use").setAttribute("href", `#icon-${iconName}`);
    dialog.classList.toggle("danger", tone === "danger");
    dialog.returnValue = "cancel";
    dialog.showModal();
    if (passkey) $("confirm-passkey").focus();
    return new Promise((resolve) => { confirmationResolve = resolve; });
}
async function importBackup(event) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    try {
        const otpAuthUris = parseBackup(await file.text());
        settingsMessage(`Importing ${otpAuthUris.length} account${otpAuthUris.length === 1 ? "" : "s"}…`);
        const result = await send("IMPORT_ENTRIES", { otpAuthUris });
        if (!result.ok) throw new Error(result.error);
        await load(true);
        const message = result.data.failed
            ? `${result.data.imported} imported; ${result.data.failed} failed.`
            : `${result.data.imported} account${result.data.imported === 1 ? "" : "s"} imported.`;
        settingsMessage(message, result.data.failed > 0);
    } catch (error) {
        settingsMessage(error.message, true);
    }
}
function parseBackup(text) {
    const otpAuthUris = text.split(/\r?\n/).map((line) => line.trim())
        .filter((line) => line && !line.startsWith("#"));
    if (!otpAuthUris.length) throw new Error("This backup does not contain any TOTP entries.");
    if (otpAuthUris.length > 500) throw new Error("A backup can contain at most 500 entries.");
    const invalidLine = otpAuthUris.findIndex((line) => !line.startsWith("otpauth://totp/"));
    if (invalidLine >= 0) throw new Error(`Invalid TOTP URI on backup entry ${invalidLine + 1}.`);
    return otpAuthUris;
}
function nextDefaultAccountName(items) {
    const highest = items.reduce((maximum, item) => {
        const match = /^Account (\d+)$/.exec(item.accountName || "");
        return match ? Math.max(maximum, Number(match[1])) : maximum;
    }, 0);
    return `Account ${highest + 1}`;
}
function formatCode(code) { return code.length === 6 ? `${code.slice(0, 3)} ${code.slice(3)}` : code; }
function escapeHtml(value) { const node = document.createElement("span"); node.textContent = value; return node.innerHTML; }
function escapeAttribute(value) { return String(value).replaceAll("&", "&amp;").replaceAll('"', "&quot;").replaceAll("'", "&#39;").replaceAll("<", "&lt;").replaceAll(">", "&gt;"); }

Promise.all([
    loadTheme().catch(() => applyTheme("system")),
    loadLocalPins().catch(() => { pinnedEntryIds = new Set(); })
]).finally(loadLockAndRoute);
renderConnectivityStatus(navigator.onLine);
checkConnectivity();
setInterval(tick, 100);
setInterval(()=>{checkConnectivity();checkActiveSession();},10000);
setInterval(() => {
    if (isAuthenticated && !$("signed-in").classList.contains("hidden") && !document.hidden) load();
}, 15000);
document.addEventListener("visibilitychange", () => {
    if (!document.hidden && isAuthenticated && !$("signed-in").classList.contains("hidden")) load();
});
window.addEventListener("online", () => {
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
