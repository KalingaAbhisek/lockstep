// Key rotation and passphrase changes between the web app and the extension, in both directions, driven through
// each client's own screens. The other client must lock at once and drop its unlocked key, reject the previous
// passphrase, accept the current one, and then support every operation, including rotating again itself.
const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = () => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Keys",email:"k@example.test",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const uri = (name, n) => `otpauth://totp/${encodeURIComponent(name)}:k?secret=${Array.from({length:16},(_, i)=>B32[(n*3+i*11)%32]).join("")}&issuer=${encodeURIComponent(name)}`;
const log = (...values) => console.log(`[${label}]`, ...values);
const control = q => fetch(`${API}/__control?${q}`).then(r => r.json());
const googleStub = "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};";
(async () => {
 await control("reset=1");
 const context = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-keys-${Date.now()}`), {
  channel:"chromium", headless:true, ignoreDefaultArgs:["--disable-extensions"],
  args:["--headless=new", `--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`] });
 const webBrowser = await chromium.launch(), webContext = await webBrowser.newContext({ acceptDownloads: true });
 try {
  await webContext.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:googleStub }));
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const extensionId = worker.url().split("/")[2];
  const errors = [];
  let P = "keys-passphrase-one";
  const web = await webContext.newPage(); web.on("pageerror", e => errors.push(`web: ${e.message}`));
  await web.goto(WEB); await web.waitForTimeout(500);
  await web.evaluate(t => onGoogleCredential({ credential: t }), token());
  await web.waitForSelector("#lock-dialog[open]");
  await web.fill("#lock-passcode", P); await web.fill("#lock-confirm", P); await web.click('#lock-form button[type="submit"]');
  await web.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await web.evaluate(us => importUris(us), [uri("Alpha", 1), uri("Bravo", 2)]);
  await worker.evaluate(async ({ t, P }) => {
   await chrome.storage.local.set({ vaultSubject:"user-1", vaultDisplayName:"Keys", appSessionId:"session-token", appSessionExpiry:Date.now()+864e5 });
   await chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() });
   await getLockConfig(); await verifyLock(P); await synchronize();
  }, { t: token(), P });
  const popup = await context.newPage(); popup.on("pageerror", e => errors.push(`popup: ${e.message}`));
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  await popup.waitForSelector("#entries .entry:not(.entry-skel)");
  for (const started = Date.now(); (await control("")).liveConnections < 2;) { if (Date.now() - started > 10000) throw Error("live channels did not connect"); await web.waitForTimeout(100); }

  const fresh = async () => {
   await web.evaluate(t => { state.token = t; sessionStorage.setItem("authsync.idToken", t); }, token());
   await worker.evaluate(async t => chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() }), token());
  };
  const visible = (page, id) => page.evaluate(id => !document.getElementById(id).classList.contains("hidden"), id);
  // The other client must lock within 3 s and hold no unlocked key.
  async function expectLocked(who, page, started) {
   await page.waitForSelector("#locked:not(.hidden)", { timeout: 3000 });
   const keyGone = who === "web" ? !await web.evaluate(() => LockstepVault.isUnlocked("user-1"))
    : !await worker.evaluate(async () => LockstepVault.isUnlocked("user-1") || Boolean((await chrome.storage.session.get("unlockedMaster")).unlockedMaster));
   assert(keyGone, `${who}: the unlocked key was kept after the change`);
   const elapsed = Date.now() - started;
   // Exactly what the Lock button leaves behind: no saved unlocked session, no codes on screen, and
   // reopening (popup) or reloading (web) stays locked.
   if (who === "web") {
    const saved = await web.evaluate(() => Object.keys(sessionStorage).filter(k => k.startsWith("authsync.session-key.") || k.startsWith("authsync.unlocked.")));
    assert.deepEqual(saved, [], `web: the unlocked session was kept after the change (${saved})`);
   } else {
    const saved = await worker.evaluate(async () => chrome.storage.session.get(["lastUnlockedAt", "unlockedMaster"]));
    assert(!saved.lastUnlockedAt && !saved.unlockedMaster, "extension: the unlocked session was kept after the change");
   }
   const codesShown = await page.evaluate(() => [...document.querySelectorAll("#entries .code, #entries [data-code]")].filter(n => n.offsetParent && /\d{3}/.test(n.textContent)).length);
   assert.equal(codesShown, 0, `${who}: codes still visible while locked`);
   await page.reload();
   await page.waitForSelector("#locked:not(.hidden), #signed-in:not(.hidden), #signed-out:not(.hidden)", { timeout: 15000 });
   await page.waitForTimeout(1500);
   assert(await visible(page, "locked") && !await visible(page, "signed-in"), `${who}: reopening after the change did not stay locked`);
   return elapsed;
  }
  async function unlock(page, passphrase) {
   // The lock screen may already explain why it locked; only the answer to this attempt counts.
   await page.evaluate(() => { document.getElementById("unlock-error").textContent = ""; document.getElementById("unlock-error").classList.add("hidden"); });
   await page.fill("#unlock-passcode", passphrase); await page.click('#unlock-form button[type="submit"]');
   await page.waitForFunction(() => !document.getElementById("signed-in").classList.contains("hidden") || document.getElementById("unlock-error").textContent.trim(), null, { timeout: 15000 });
   const error = (await page.textContent("#unlock-error")).trim();
   await page.evaluate(() => { document.getElementById("unlock-error").textContent = ""; });
   return (await visible(page, "signed-in")) ? "unlocked" : error;
  }
  async function unlockRejectingOld(who, page, old, current) {
   if (old) assert.match(await unlock(page, old), /Incorrect passphrase/, `${who} accepted the previous passphrase`);
   assert.equal(await unlock(page, current), "unlocked", `${who} did not accept the current passphrase`);
  }
  // Every operation after unlocking: add, rename, show a QR code, delete (with passphrase), plus convergence.
  let counter = 10;
  async function operations(who) {
   const name = `${who} ${++counter}`;
   if (who === "web") {
    await web.click("#open-add"); await web.click("#open-manual");
    await web.fill("#manual-issuer", name); await web.fill("#manual-account", "k"); await web.fill("#manual-secret", "JBSWY3DPEHPK3PXP");
    await web.click("#manual-form button[type=submit]");
    await web.waitForFunction(n => [...document.querySelectorAll("#entries .issuer")].some(x => x.textContent === n), name);
    await web.evaluate(async n => { const e = (await LockstepVault.listEntries("user-1")).find(x => x.issuer === n); await LockstepVault.updateEntry("user-1", e.id, `${n} renamed`, "k"); await syncVault(); }, name);
    await web.click("#entries .entry [data-action=qr]"); await web.waitForSelector("#qr-image:not(.hidden)"); await web.click("#close-qr");
    const victim = await web.evaluate(async n => (await LockstepVault.listEntries("user-1")).find(x => x.issuer === `${n} renamed`).id, name);
    await web.click("#edit-accounts");
    await web.click(`#entries .entry[data-id="${victim}"] [data-action=delete]`);
    await web.waitForSelector("#confirm-dialog[open]"); await web.fill("#confirm-passkey", P); await web.click("#confirm-accept");
    await web.waitForFunction(id => !document.querySelector(`#entries .entry[data-id="${id}"]`), victim, { timeout: 15000 });
    await web.click("#save-edits");
   } else {
    const send = (type, data) => popup.evaluate(([type, data]) => send(type, data), [type, data]);
    const added = await send("ADD_OTP_URI", { otpAuthUri: uri(name, counter) }); assert(added.ok, `extension add: ${added.error}`);
    const renamed = await send("UPDATE_ENTRY", { id: added.data.id, issuer: `${name} renamed`, accountName: "k" }); assert(renamed.ok, `extension rename: ${renamed.error}`);
    const qr = await send("GET_ENTRY_QR", { id: added.data.id }); assert(qr.ok && qr.data.startsWith("otpauth://totp/"), `extension QR: ${qr.error}`);
    const removed = await send("DELETE_ENTRY", { id: added.data.id, passcode: P }); assert(removed.ok, `extension delete: ${removed.error}`);
   }
   // Both clients agree and open every account.
   for (const started = Date.now(); ; await web.waitForTimeout(250)) {
    const w = await web.evaluate(async () => (await LockstepVault.listEntries("user-1")).map(e => e.error ? `!${e.issuer}` : e.issuer).sort().join("|"));
    const x = await worker.evaluate(async () => (await LockstepVault.listEntries("user-1")).map(e => e.error ? `!${e.issuer}` : e.issuer).sort().join("|"));
    if (w === x && !w.includes("!")) break;
    if (Date.now() - started > 10000) throw Error(`${who} operations: clients differ: web ${w} / extension ${x}`);
   }
  }
  async function webRotate() {
   await fresh(); await web.click("#open-settings"); await web.click("#settings-key-rotate");
   await web.waitForSelector("#confirm-dialog[open]"); await web.fill("#confirm-passkey", P);
   const started = Date.now(); await web.click("#confirm-accept");
   await web.waitForFunction(() => /rotated to version/.test(document.getElementById("toast").textContent), null, { timeout: 30000 });
   return started;
  }
  async function popupRotate() {
   await fresh(); await popup.click("#settings"); await popup.waitForTimeout(400); await popup.click("#settings-key-rotate");
   await popup.waitForSelector("#confirm-dialog[open]"); await popup.fill("#confirm-passkey", P);
   const started = Date.now(); await popup.click("#confirm-accept");
   await popup.waitForFunction(() => /rotated to version/.test(document.getElementById("settings-message").textContent), null, { timeout: 30000 });
   await popup.click("#settings-back"); await popup.waitForTimeout(400);
   return started;
  }
  async function webChangePassphrase(next) {
   await fresh(); await web.click("#open-settings"); await web.click("#settings-lock");
   await web.fill("#lock-passcode", next); await web.fill("#lock-confirm", next);
   const started = Date.now(); await web.click('#lock-form button[type="submit"]');
   await web.waitForFunction(() => !document.getElementById("lock-dialog").open, null, { timeout: 30000 });
   return started;
  }
  async function popupChangePassphrase(next) {
   await fresh(); await popup.click("#settings"); await popup.waitForTimeout(400); await popup.click("#settings-lock");
   await popup.fill("#lock-passcode", next); await popup.fill("#lock-confirm", next);
   const started = Date.now(); await popup.click('#lock-form button[type="submit"]');
   await popup.waitForFunction(() => /Lock protection saved/.test(document.getElementById("settings-message").textContent), null, { timeout: 30000 });
   await popup.waitForTimeout(400); // saving returns to the account list by itself
   if (await visible(popup, "settings-back")) { await popup.click("#settings-back"); await popup.waitForTimeout(400); }
   return started;
  }
  const keyVersion = () => control("").then(s => s.keyVersion);

  // Rotation: web -> extension locks -> unlock -> operations -> extension rotates -> web locks -> unlock -> web rotates.
  let t = await webRotate();
  log(`web rotation (key ${await keyVersion()}): extension locked after ${await expectLocked("extension", popup, t)} ms`);
  await unlockRejectingOld("extension", popup, null, P); await operations("extension");
  t = await popupRotate();
  log(`extension rotation after unlocking (key ${await keyVersion()}): web locked after ${await expectLocked("web", web, t)} ms`);
  await unlockRejectingOld("web", web, null, P); await operations("web");
  t = await webRotate();
  log(`web rotation after unlocking (key ${await keyVersion()}): extension locked after ${await expectLocked("extension", popup, t)} ms`);
  await unlockRejectingOld("extension", popup, null, P); await operations("extension");

  // Passphrase changes: the other client locks, rejects the previous passphrase and accepts the new one.
  let old = P; P = "keys-passphrase-two";
  t = await popupChangePassphrase(P);
  log(`extension passphrase change: web locked after ${await expectLocked("web", web, t)} ms`);
  await unlockRejectingOld("web", web, old, P); await operations("web");
  old = P; P = "keys-passphrase-three";
  t = await webChangePassphrase(P);
  log(`web passphrase change: extension locked after ${await expectLocked("extension", popup, t)} ms`);
  await unlockRejectingOld("extension", popup, old, P); await operations("extension");

  assert.deepEqual(errors, []);
  log("rotations and passphrase changes in both directions: lock, unlock and every operation succeeded");
 } finally { await context.close(); await webBrowser.close(); }
})().catch(error => { console.error(`[${label}] FAILED`, error); process.exitCode = 1; });
