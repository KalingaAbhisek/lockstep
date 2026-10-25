const API = `http://localhost:${process.env.API_PORT || 8080}`;
// Vault revision (no device can overwrite a newer key), saved delta cursor, refused stale changes,
// rotation guard, sealed session key and "sign out of all devices". Two browser contexts = two devices.
const { chromium } = require("playwright");
const [label, port] = [process.argv[2], process.argv[3]];
const base = `http://localhost:${port}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJwt = `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Test User",email:"t@example.com",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };
const P1 = "first-passphrase-1", P2 = "second-passphrase-2", P3 = "third-passphrase-3", P4 = "fourth-passphrase-4";
const count = (page) => page.$$eval("#entries .entry:not(.entry-skel)", n => n.length);
const names = (page) => page.$$eval("#entries .entry:not(.entry-skel) .issuer", n => n.map(x => x.textContent));
const waitCount = (page, n) => page.waitForFunction(c => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === c, n, { timeout: 20000 });

async function device(browser) {
  const context = await browser.newContext({ acceptDownloads: true, serviceWorkers: "block" });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType: "application/javascript", body: "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  await context.route("https://accounts.google.com/gsi/style", r => r.fulfill({ contentType: "text/css", body: "/* Google stylesheet fixture */" }));
  const page = await context.newPage();
  page.errors = []; page.on("pageerror", e => page.errors.push(e.message));
  await page.goto(base); await page.waitForTimeout(800);
  await page.evaluate(t => onGoogleCredential({ credential: t }), fakeJwt);
  return page;
}
async function unlock(page, passphrase) {
  await page.waitForSelector("#locked:not(.hidden)", { timeout: 15000 });
  await page.fill("#unlock-passcode", passphrase); await page.click("#unlock-form button[type=submit]");
}
async function changePassphrase(page, passphrase) {
  await page.click("#open-settings"); await page.click("#settings-lock");
  await page.waitForSelector("#lock-dialog[open]");
  await page.fill("#lock-passcode", passphrase); await page.fill("#lock-confirm", passphrase);
  await page.click("#lock-form button[type=submit]");
}
async function addManual(page, issuer, secret) {
  await page.click("#open-add"); await page.click("#open-manual");
  await page.fill("#manual-issuer", issuer); await page.fill("#manual-account", `${issuer.toLowerCase()}@example.com`); await page.fill("#manual-secret", secret);
  await page.click("#manual-form button[type=submit]");
}

(async () => {
  await control("reset=1");
  const browser = await chromium.launch();

  // Device A: new account, passphrase P1, two accounts.
  const a = await device(browser);
  await a.waitForSelector("#lock-dialog[open]");
  await a.fill("#lock-passcode", P1); await a.fill("#lock-confirm", P1);
  await a.click("#lock-form button[type=submit]");
  await a.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await addManual(a, "Alpha", "JBSWY3DPEHPK3PXP"); await waitCount(a, 1);
  await addManual(a, "Bravo", "GEZDGNBVGY3TQOJQ"); await waitCount(a, 2);
  await a.waitForTimeout(1500);
  let st = await control("");
  log("setup: server revision", st.revision, "| accounts", st.entries.length);
  check(st.revision === 1, "the first passphrase did not set revision 1");

  // Sealed session key: no readable vault key in sessionStorage, and a reload still resumes the open vault.
  const stored = await a.evaluate(() => JSON.parse(sessionStorage.getItem(Object.keys(sessionStorage).find(k => k.startsWith("authsync.session-key.")))));
  check(stored && stored.sealed && !stored.raw, "the unlocked vault key is stored readable in sessionStorage");
  // Saved delta cursor: the next startup only asks for changes, and remote changes still arrive.
  await control("remoteRename=1"); await control("clearCalls=1");
  await a.reload();
  await waitCount(a, 2);
  await a.waitForFunction(() => [...document.querySelectorAll("#entries .issuer")].some(n => n.textContent === "Renamed elsewhere"), null, { timeout: 15000 });
  st = await control("");
  const startup = st.calls.find(c => c.startsWith("GET /api/v1/bootstrap"));
  log("sealed session key:", Boolean(stored?.sealed && !stored?.raw), "| reload resumed unlocked:", await a.isVisible("#signed-in"), "| startup request:", startup, "| names:", JSON.stringify(await names(a)));
  check(/since=\d+/.test(startup || ""), "the startup request did not use the saved cursor");
  check(await a.isVisible("#signed-in"), "reload did not resume the unlocked vault");
  await control("remoteDelete=1"); await control("clearCalls=1");
  await a.reload();
  await waitCount(a, 1);
  log("remote deletion applied through delta startup:", (await count(a)) === 1);

  // Device B signs in, unlocks with P1 and changes the passphrase to P2 (server revision 2).
  const b = await device(browser);
  await unlock(b, P1); await waitCount(b, 1);
  await changePassphrase(b, P2);
  await b.waitForFunction(() => !document.getElementById("lock-dialog").open, null, { timeout: 20000 });
  st = await control("");
  const keyFromB = st.wrappedKey;
  log("device B changed passphrase: revision", st.revision);
  check(st.revision === 2, "device B's passphrase change did not raise the revision");

  // Device A's clock runs far ahead (its key looks "newer"). It must still take the server's key, never upload its own.
  await a.evaluate(async () => {
    const db = await new Promise((resolve, reject) => { const r = indexedDB.open("lockstep-vault"); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    const tx = db.transaction("keys", "readwrite"); const store = tx.objectStore("keys");
    const record = await new Promise(resolve => { const r = store.get("user-1:master"); r.onsuccess = () => resolve(r.result); });
    record.wrappedAt = Date.now() + 365 * 24 * 3600 * 1000; store.put(record);
    await new Promise(resolve => { tx.oncomplete = resolve; });
  });
  await a.click("#lock-now");
  await a.reload();
  await unlock(a, P1);
  await a.waitForTimeout(3000);
  st = await control("");
  const p1Message = (await a.textContent("#unlock-error")).trim();
  log("device A (clock ahead) with old passphrase:", p1Message || "(no message)", "| server key unchanged:", st.wrappedKey === keyFromB, "| revision", st.revision);
  check(st.wrappedKey === keyFromB, "a device with a fast clock overwrote the newer wrapped key");
  check(!(await a.isVisible("#signed-in")), "the old passphrase still opened the vault after another device changed it");
  await a.fill("#unlock-passcode", P2); await a.click("#unlock-form button[type=submit]");
  await waitCount(a, 1);
  log("device A unlocked with the new passphrase");

  // Conflict: B changes to P3 while A (not yet synced) changes to P4. A must be refused and take B's key.
  await changePassphrase(b, P3);
  await b.waitForFunction(() => !document.getElementById("lock-dialog").open, null, { timeout: 20000 });
  const keyFromB3 = (await control("")).wrappedKey;
  await changePassphrase(a, P4);
  await a.waitForSelector("#locked:not(.hidden)", { timeout: 20000 });
  st = await control("");
  log("concurrent change refused:", (await a.textContent("#toast")).trim(), "| server keeps B's key:", st.wrappedKey === keyFromB3, "| revision", st.revision);
  check(st.wrappedKey === keyFromB3, "a stale passphrase change overwrote another device's change");
  await a.fill("#unlock-passcode", P3); await a.click("#unlock-form button[type=submit]");
  await waitCount(a, 1);

  // An account the server refuses for good (added with a rotated-away key) leaves the queue, so it is not retried
  // forever, but it is kept on this device and marked as such, never silently lost.
  await control("staleNextAdd=1");
  await addManual(a, "Stale", "MFRGGZDFMZTWQ2LK");
  await a.waitForFunction(() => /previous recovery key/.test(document.getElementById("toast").textContent), null, { timeout: 20000 });
  const pending = await a.evaluate(() => LockstepVault.pendingCount("user-1"));
  await addManual(a, "Charlie", "GEZDGNBVGY3TQOJQ");
  await a.waitForTimeout(2500);
  await a.click("#open-settings"); await a.click("#settings-refresh");
  await a.waitForTimeout(2500);
  st = await control("");
  log("refused change dropped:", pending === 0, "| later change synced:", st.entries.some(e => e.startsWith("Encrypted") || e.startsWith("Charlie")), "| server accounts:", st.entries.length, "| on screen:", JSON.stringify(await names(a)));
  check(pending === 0, "a refused change stayed in the queue");
  check(st.entries.length === 2, "the change after a refused one did not reach the server");
  check((await names(a)).includes("Stale"), "an account the server refused was lost instead of kept on this device");
  const badge = await a.evaluate(() => [...document.querySelectorAll("#entries .entry")].some(n => n.querySelector(".local-only-label")));
  check(badge, "the refused account is not marked as only on this device");

  // An account kept only on this device blocks a rotation (it would be lost); once removed, rotation is allowed.
  const blockedByKept = await a.evaluate((passphrase) => LockstepVault.prepareMasterRotation("user-1", passphrase).then(p => { LockstepVault.cancelMasterRotation(p); return null; }, e => e.message), P3);
  check(/kept on this device only/.test(blockedByKept || ""), "a rotation was allowed while an account existed only on this device");
  await a.evaluate(async () => {
    for (const entry of (await LockstepVault.listEntries("user-1")).filter(e => e.localOnly)) await LockstepVault.deleteEntry("user-1", entry.id);
    await loadEntries(true);
  });
  await a.waitForTimeout(1500);

  // No local change can slip in while the recovery key is being rotated.
  const guard = await a.evaluate(async (passphrase) => {
    const prepared = await LockstepVault.prepareMasterRotation("user-1", passphrase);
    let blocked = null;
    try { await LockstepVault.addOtpUri("user-1", "otpauth://totp/X:x@example.com?secret=JBSWY3DPEHPK3PXP&issuer=X"); } catch (error) { blocked = error.code; }
    LockstepVault.cancelMasterRotation(prepared);
    const synced = await LockstepVault.pendingCount("user-1");
    return { blocked, pendingAfter: synced };
  }, P3);
  log("change during rotation:", guard.blocked);
  check(guard.blocked === "ROTATION_IN_PROGRESS", "a local change was accepted during a key rotation");

  // Sign out of all devices.
  await a.click("#open-settings"); await a.click("#settings-signout-all");
  await a.waitForSelector("#confirm-dialog[open]"); await a.click("#confirm-accept");
  await a.waitForSelector("#signed-out:not(.hidden)", { timeout: 15000 });
  st = await control("");
  log("signed out of all devices:", st.signedOutAll === 1, "| server session:", st.session, "| toast:", (await a.textContent("#toast")).trim());
  check(st.signedOutAll === 1 && st.session === null, "sign out of all devices did not end the server sessions");

  const errors = [...a.errors, ...b.errors];
  check(errors.length === 0, `page errors: ${errors}`);
  log("errors:", errors.length ? errors : "none");
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
