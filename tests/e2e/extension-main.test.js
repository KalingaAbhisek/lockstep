const API = `http://localhost:${process.env.API_PORT || 8080}`;
const { chromium } = require("playwright");
const [label, extDir] = [process.argv[2], process.argv[3]];
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
// A Google ID token issued just now (the mock checks only its claims), so key-changing actions are allowed.
const freshGoogleToken = () => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Test User",email:"t@example.com",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };

const secrets = ["JBSWY3DPEHPK3PXP","GEZDGNBVGY3TQOJQ","MFRGGZDFMZTWQ2LK","ONSWG4TFOQYTEMZU","KRSXG5BAMFZGK3TP"];
const uris = secrets.map((s,i)=>`otpauth://totp/Issuer${i}:user${i}@example.com?secret=${s}&issuer=Issuer${i}&period=15`);
(async () => {
  await control("reset=1"); if (process.env.OLDSERVER) await control("nobootstrap=1");
  await fetch(`${API}/api/v1/session`, { method: "POST" });
  const context = await chromium.launchPersistentContext(require("path").join(require("os").tmpdir(), `lockstep-profile-${label}-${Date.now()}`), {
    channel: "chromium", headless: true,
    ignoreDefaultArgs: ["--disable-extensions"], args: ["--headless=new", `--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`] });
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const extensionId = worker.url().split("/")[2];
  // Wait from here until the worker has started (asking too early can run before its timers exist).
  for (let i = 0; i < 100; i++) {
    if (await worker.evaluate(() => Boolean(globalThis.chrome?.storage) && typeof setTimeout === "function").catch(() => false)) break;
    await new Promise(r => setTimeout(r, 100));
  }
  // Seed a signed-in device and create the vault with the worker's own functions.
  const setup = await worker.evaluate(async ({ uris, token }) => {
    await chrome.storage.local.set({ vaultSubject: "user-1", vaultDisplayName: "Test User", appSessionId: "session-token", appSessionExpiry: Date.now() + 864e5 });
    await chrome.storage.session.set({ idToken: token, tokenExpiry: Date.now() + 3600e3, interactiveSignInAt: Date.now() });
    await chrome.storage.session.set({ newAccountSetupAuthorized: true });
    const config = await setLockConfig("1234pass-long", 300, false, true);
    const result = await importEntries(uris);
    return { lock: config.enabled, imported: result.imported };
  }, { uris, token: freshGoogleToken() });
  log("setup:", JSON.stringify(setup), "server entries:", (await control("")).entries.length);
  await control("clearCalls=1");
  const page = await context.newPage();
  const errors = []; page.on("pageerror", e => errors.push(e.message));
  const started = Date.now();
  await page.goto(`chrome-extension://${extensionId}/popup.html`);
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 5, null, { timeout: 20000 });
  log(`popup codes visible after ${Date.now() - started} ms`);
  await page.waitForTimeout(3000);
  log("popup open calls:", JSON.stringify((await control("")).calls));
  await control("clearCalls=1");
  const before = await page.$$eval("#entries .entry .code", n => n.map(x => x.textContent));
  await page.waitForTimeout(16500);
  const after = await page.$$eval("#entries .entry .code", n => n.map(x => x.textContent));
  log("codes changed at rollover:", before.some((c, i) => c !== after[i]), "calls during 16.5s:", JSON.stringify((await control("")).calls));
  await page.click("#entries .entry [data-action=qr]");
  await page.waitForFunction(() => { const i = document.getElementById("qr-image"); return i.src.startsWith("data:image"); }, null, { timeout: 10000 });
  log("QR code rendered: yes");
  // Import more through the worker to exercise batching.
  await control("clearCalls=1");
  const more = ["NBSWY3DPO5XXE3DE","MZXW6YTBOI======"].map((s,i)=>`otpauth://totp/More${i}:m${i}@example.com?secret=${s}&issuer=More${i}`);
  await worker.evaluate(async (u) => importEntries(u), more);
  log("import 2 calls:", JSON.stringify((await control("")).calls), "server entries:", (await control("")).entries.length);
  const unlockChecks = await worker.evaluate(async () => {
    await lockVault();
    let wrong; try { await verifyLock("wrong-passkey"); wrong = "unlocked?!"; } catch (e) { wrong = e.message; }
    const right = await verifyLock("1234pass-long");
    return { wrong, right: right.unlocked };
  });
  log("extension unlock checks:", JSON.stringify(unlockChecks));
  // Exports need the passphrase again; a backup can be encrypted and opened again with its password.
  const exports = await worker.evaluate(async () => {
    const wrong = await exportEntries("not-the-passphrase").then(() => "exported?!", (e) => e.code);
    const recoveryWrong = await exportRecoveryKey("not-the-passphrase").then(() => "exported?!", (e) => e.code);
    const plain = await exportEntries("1234pass-long");
    const encrypted = await exportEntries("1234pass-long", "backup-password-123");
    const reopened = await LockstepVault.decryptBackup(encrypted, "backup-password-123");
    const wrongPassword = await LockstepVault.decryptBackup(encrypted, "wrong-password-000").then(() => "opened?!", (e) => e.code);
    return { wrong, recoveryWrong, plainHasUris: plain.includes("otpauth://totp/"), encryptedHidesUris: !encrypted.includes("otpauth"),
      roundTrip: reopened === plain, wrongPassword, format: JSON.parse(encrypted).format };
  });
  log("extension exports:", JSON.stringify(exports));
  check(exports.wrong === "WRONG_PASSKEY" && exports.recoveryWrong === "WRONG_PASSKEY", "an extension export went ahead without the passphrase");
  check(exports.plainHasUris && exports.encryptedHidesUris && exports.roundTrip && exports.wrongPassword === "WRONG_BACKUP_PASSWORD", "the extension's encrypted backup did not round-trip");
  // The same through the popup: passphrase prompt, then the backup-password dialog, then the download.
  await page.evaluate(() => { exportBackup(); });
  await page.waitForSelector("#confirm-dialog[open]");
  await page.fill("#confirm-passkey", "1234pass-long"); await page.click("#confirm-accept");
  await page.waitForSelector("#backup-dialog[open]", { timeout: 15000 });
  await page.fill("#backup-password", "backup-password-123"); await page.fill("#backup-password-confirm", "backup-password-123");
  const [popupDownload] = await Promise.all([page.waitForEvent("download", { timeout: 30000 }), page.click("#backup-accept")]);
  const popupFile = require("fs").readFileSync(await popupDownload.path(), "utf8");
  log("popup encrypted export:", popupDownload.suggestedFilename(), "| hides secrets:", !popupFile.includes("otpauth"));
  check(popupDownload.suggestedFilename().endsWith(".json") && JSON.parse(popupFile).format === "lockstep-encrypted-backup" && !popupFile.includes("otpauth"), "the popup did not export an encrypted backup");
  const recovery = await worker.evaluate(async () => {
    const owner = await subject();
    const original = await LockstepVault.exportWrappedKey(owner);          // wrapped with 1234pass
    // The open popup refreshes in the background; make sure the vault is still open before changing the key here.
    for (let i = 0; i < 3 && !LockstepVault.isUnlocked(owner); i++) await verifyLock("1234pass-long").catch(() => null);
    await LockstepVault.configurePassphrase(owner, "otherpass99-long");         // this device now uses a newer passkey
    // Another (current) device uploads its key, saying which vault revision it expects.
    const expectedRevision = (await api("/api/v1/lock")).vaultRevision;
    await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ timeoutSeconds: 300, lockOnScreenLock: false, wrappedKey: original, expectedRevision }) });
    await lockVault();
    try { await verifyLock("1234pass-long"); return "unlocked?!"; } catch (e) { return `${e.code}: ${e.message}`; }
  });
  log("passkey changed elsewhere:", recovery);
  // The web app changes the passkey: it re-wraps the same vault key with the new passkey and uploads only
  // that wrapped key (newer timestamp). The extension must then unlock with the new passkey only.
  const webChange = await worker.evaluate(async () => {
    const owner = await subject();
    for (let i = 0; i < 3 && !LockstepVault.isUnlocked(owner); i++) await verifyLock("otherpass99-long").catch(() => null); // this device's current passkey
    await LockstepVault.configurePassphrase(owner, "web-new-pass-long");            // stand-in for the web app re-wrapping
    const fromWeb = { ...(await LockstepVault.exportWrappedKey(owner)), wrappedAt: Date.now() + 5000 };
    await LockstepVault.configurePassphrase(owner, "otherpass99-long");            // put this device back on its old passkey
    const expectedRevision = (await api("/api/v1/lock")).vaultRevision;
    await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ timeoutSeconds: 300, lockOnScreenLock: false, wrappedKey: fromWeb, expectedRevision }) });
    await lockVault();
    let oldPasskey; try { await verifyLock("otherpass99-long"); oldPasskey = "unlocked"; } catch (e) { oldPasskey = e.message; }
    let newPasskey; try { newPasskey = (await verifyLock("web-new-pass-long")).unlocked ? "unlocked" : "?"; } catch (e) { newPasskey = e.message; }
    const codes = (await localEntries()).length;
    return { oldPasskey, newPasskey, codesAfterUnlock: codes };
  });
  log("passkey changed in web app:", JSON.stringify(webChange));
  check((await control("")).passcodeSeen === 0, "a request contained the passphrase");
  log("requests that contained a passkey:", (await control("")).passcodeSeen);
  let st = await control("");
  log("names on server after migration:", st.encrypted, "of", st.entries.length, "encrypted");
  // Atomic recovery-key rotation through the worker (as the popup's Settings button does).
  await control("clearCalls=1");
  const rotation = await worker.evaluate(async () => {
    await verifyLock("web-new-pass-long").catch(() => null);
    try { const result = await rotateEncryptionKey("web-new-pass-long"); return { version: result.version, count: result.count, recovery: result.recoveryKey.startsWith("LS2-M-") }; }
    catch (e) { return { error: e.message }; }
  });
  st = await control("");
  log("extension rotation:", JSON.stringify(rotation), "| server key version:", st.keyVersion, "| writes:", JSON.stringify(st.calls.filter(c => !c.startsWith("GET"))));
  const afterRotation = await worker.evaluate(async () => { await lockVault(); await verifyLock("web-new-pass-long"); return (await localEntries()).map(e => e.issuer).slice(0, 2); });
  log("unlock + names after rotation:", JSON.stringify(afterRotation));
  if (!process.env.OLDSERVER) {
    // Another device changes the passphrase while this device's clock runs far ahead: this device must take
    // the server's key (never upload its own), and the old passphrase no longer opens the vault.
    const skew = await worker.evaluate(async () => {
      const owner = await subject();
      await LockstepVault.configurePassphrase(owner, "elsewhere-pass-long");
      const fromOther = await LockstepVault.exportWrappedKey(owner);
      await LockstepVault.configurePassphrase(owner, "web-new-pass-long");
      const expectedRevision = (await api("/api/v1/lock")).vaultRevision;
      await LockstepVault.markWrappedKeySynced(owner, expectedRevision, await LockstepVault.exportWrappedKey(owner));
      await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ timeoutSeconds: 300, lockOnScreenLock: false, wrappedKey: fromOther, expectedRevision }) });
      const db = await new Promise(resolve => { const r = indexedDB.open("lockstep-vault"); r.onsuccess = () => resolve(r.result); });
      const tx = db.transaction("keys", "readwrite"); const store = tx.objectStore("keys");
      const record = await new Promise(resolve => { const r = store.get(owner + ":master"); r.onsuccess = () => resolve(r.result); });
      record.wrappedAt = Date.now() + 365 * 24 * 3600 * 1000; store.put(record);
      await new Promise(resolve => { tx.oncomplete = resolve; });
      await lockVault();
      let oldPassphrase; try { await verifyLock("web-new-pass-long"); oldPassphrase = "unlocked"; } catch (e) { oldPassphrase = e.message; }
      const serverKeyKept = (await api("/api/v1/lock")).wrappedKey.wrappedMasterKey === fromOther.wrappedMasterKey;
      const newPassphrase = (await verifyLock("elsewhere-pass-long")).unlocked;
      return { oldPassphrase, serverKeyKept, newPassphrase };
    });
    log("clock ahead, key changed elsewhere:", JSON.stringify(skew));
    check(skew.serverKeyKept && skew.oldPassphrase !== "unlocked" && skew.newPassphrase, "the extension overwrote or ignored a newer wrapped key");
    // Refused stale change is dropped; no local change during a rotation.
    await control("staleNextAdd=1");
    const guards = await worker.evaluate(async () => {
      const owner = await subject();
      await addOtpUri("otpauth://totp/Stale:s@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Stale").catch(() => null);
      const pendingAfterStale = await LockstepVault.pendingCount(owner);
      // The refused account is kept on this device (marked local-only), and blocks a rotation until it is removed.
      const kept = (await LockstepVault.listEntries(owner)).filter(e => e.localOnly);
      for (const entry of kept) await deleteEntry(entry.id, "elsewhere-pass-long"); // confirmed removal
      const prepared = await LockstepVault.prepareMasterRotation(owner, "elsewhere-pass-long");
      let blocked = null; try { await LockstepVault.addOtpUri(owner, "otpauth://totp/X:x@example.com?secret=JBSWY3DPEHPK3PXP&issuer=X"); } catch (e) { blocked = e.code; }
      LockstepVault.cancelMasterRotation(prepared);
      return { pendingAfterStale, keptLocally: kept.length, syncError: lastSyncError, blocked };
    });
    log("refused change + rotation guard:", JSON.stringify(guards));
    check(guards.pendingAfterStale === 0 && guards.keptLocally === 1 && guards.blocked === "ROTATION_IN_PROGRESS", "stale change retried, lost instead of kept locally, or change accepted during rotation");
  }
  // A script running inside a web page may only add a scanned account.
  const tab = await context.newPage(); await tab.goto(`${API}/__page`);
  const fromPage = await worker.evaluate(async (api) => {
    const [tab] = await chrome.tabs.query({ url: `${api}/*` });
    const [{ result }] = await chrome.scripting.executeScript({ target: { tabId: tab.id }, func: async () => {
      const exported = await chrome.runtime.sendMessage({ type: "EXPORT_ENTRIES" });
      const reset = await chrome.runtime.sendMessage({ type: "RESET_VAULT" });
      return { exported, reset };
    } });
    return result;
  }, API);
  check(fromPage.exported.ok === false && fromPage.reset.ok === false, "a web page script could use privileged actions");
  log("content-script EXPORT/RESET:", JSON.stringify(fromPage));
  if (process.env.ARGON2ID !== "0" && !process.env.OLDSERVER) {
    // Argon2id is on by default: the vault key is protected with it (re-protected at unlock if it was set up earlier).
    const wrapping = (await control("")).wrapping;
    check(wrapping === "ARGON2ID-V13/AES-256-GCM", `vault key not re-protected with Argon2id (${wrapping})`);
    const reopened = await worker.evaluate(async () => { await lockVault(); return (await verifyLock("elsewhere-pass-long")).unlocked; });
    check(reopened, "the Argon2id-protected vault did not unlock");
    log("vault key protection after unlock:", wrapping, "| unlocks again:", reopened);
  }
  await control("clearCalls=1");
  // Current servers: "Sign out of all devices"; old-server run: the normal sign-out.
  await worker.evaluate(async (all) => { if (all) await logoutEverywhere(); else await logout(); }, !process.env.OLDSERVER);
  st = await control("");
  check(st.session === null, "extension sign-out did not end the server session");
  if (!process.env.OLDSERVER) check(st.signedOutAll === 1 && st.calls.includes("DELETE /api/v1/session?all=true"), "sign out of all devices did not reach the server");
  log("extension sign-out calls:", JSON.stringify(st.calls), "| server session:", st.session);
  check(errors.length === 0, `page errors: ${errors}`);
  log("errors:", errors.length ? errors : "none");
  await context.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
