// A passphrase change must treat the other client's vault and its operations exactly like a key rotation does.
// For each kind of change (passphrase, rotation) and each direction (web -> extension, extension -> web):
// the other client is cut off from the server and adds an account while the change happens elsewhere. When it
// reconnects it must lock (key and saved session gone), refuse every operation while locked, refuse the old
// passphrase (passphrase change) and open with the current one, upload the account it added while cut off
// (nothing lost, nothing left "only on this device"), and then support every operation; both clients converge.
const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = () => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Pending",email:"k@example.test",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const uri = (name, n) => `otpauth://totp/${encodeURIComponent(name)}:k?secret=${Array.from({length:16},(_, i)=>B32[(n*3+i*11)%32]).join("")}&issuer=${encodeURIComponent(name)}`;
const log = (...values) => console.log(`[${label}]`, ...values);
const control = q => fetch(`${API}/__control?${q}`).then(r => r.json());
const googleStub = "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};";
(async () => {
 await control("reset=1");
 const context = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-pending-${Date.now()}`), {
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
   await chrome.storage.local.set({ vaultSubject:"user-1", vaultDisplayName:"Pending", appSessionId:"session-token", appSessionExpiry:Date.now()+864e5 });
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
  // Locked: key and saved unlocked session gone, no codes on screen, and every operation refused.
  async function waitLocked(who, page, started) {
   await page.waitForSelector("#locked:not(.hidden)", { timeout: 25000 });
   const elapsed = Date.now() - started;
   if (who === "web") {
    assert(!await web.evaluate(() => LockstepVault.isUnlocked("user-1")), "web: key kept after locking");
    const saved = await web.evaluate(() => Object.keys(sessionStorage).filter(k => k.startsWith("authsync.session-key.")));
    assert.deepEqual(saved, [], "web: unlocked session kept after locking");
    const refused = await web.evaluate(async u => { try { await LockstepVault.addOtpUri("user-1", u); return "accepted"; } catch (e) { return e.code || e.message; } }, uri("Refused web", 90));
    assert.notEqual(refused, "accepted", "web: an account was added while locked");
   } else {
    const s = await worker.evaluate(async () => ({ open: LockstepVault.isUnlocked("user-1"), ...(await chrome.storage.session.get(["lastUnlockedAt", "unlockedMaster"])) }));
    assert(!s.open && !s.lastUnlockedAt && !s.unlockedMaster, "extension: key or unlocked session kept after locking");
    for (const [type, data] of [["LIST_ENTRIES", {}], ["ADD_OTP_URI", { otpAuthUri: uri("Refused ext", 91) }], ["GET_ENTRY_QR", { id: "x" }], ["EXPORT_BACKUP", {}]]) {
     const r = await popup.evaluate(([type, data]) => chrome.runtime.sendMessage({ type, ...data }), [type, data]);
     assert(!r?.ok, `extension: ${type} worked while locked`);
    }
   }
   const codes = await page.evaluate(() => [...document.querySelectorAll("#entries .code")].filter(n => n.offsetParent && /\d{3}/.test(n.textContent)).length);
   assert.equal(codes, 0, `${who}: codes visible while locked`);
   return elapsed;
  }
  async function addWhileCutOff(who, name, n) {
   if (who === "web") await web.evaluate(u => handleCameraResult(u), uri(name, n));
   else { const r = await popup.evaluate(u => send("ADD_OTP_URI", { otpAuthUri: u }), uri(name, n)); assert(r.ok, `extension add while cut off: ${r.error}`); }
   const page = who === "web" ? web : popup;
   await page.waitForFunction(n => [...document.querySelectorAll("#entries .issuer")].some(x => x.textContent === n), name, { timeout: 10000 });
  }
  async function converged(label, names) {
   for (const started = Date.now(); ; await web.waitForTimeout(300)) {
    const server = (await control("")).entries; // names are encrypted on the server: compare the count
    const w = await web.evaluate(async () => (await LockstepVault.listEntries("user-1")).map(e => e.error ? `!${e.issuer}` : e.issuer).sort().join("|"));
    const x = await worker.evaluate(async () => (await LockstepVault.listEntries("user-1")).map(e => e.error ? `!${e.issuer}` : e.issuer).sort().join("|"));
    const local = await Promise.all([web.evaluate(() => document.body.innerText.includes("Only on this device")), popup.evaluate(() => document.body.innerText.includes("Only on this device"))]);
    if (w === x && !w.includes("!") && server.length === w.split("|").length && names.every(n => w.split("|").includes(n)) && !local.some(Boolean)) return;
    if (Date.now() - started > 30000) throw Error(`${label}: not converged: server ${server.length} accounts / web ${w} / extension ${x} / only-local ${local}`);
   }
  }

  const changes = {
   passphrase: { web: next => webChangePassphrase(next), extension: next => popupChangePassphrase(next) },
   rotation: { web: () => webRotate(), extension: () => popupRotate() }
  };
  let n = 40; const added = [];
  for (const kind of ["passphrase", "rotation"]) for (const [from, to] of [["web", "extension"], ["extension", "web"]]) {
   const label = `${kind} ${from} -> ${to}`, page = to === "web" ? web : popup, name = `Cut off ${++n}`;
   await control(`blockClient=${to}`);
   await addWhileCutOff(to, name, n); added.push(name);
   const old = P; if (kind === "passphrase") P = `pending-passphrase-${n}`;
   await changes[kind][from](P);
   await web.waitForTimeout(1500);
   assert(!await visible(page, "locked"), `${label}: ${to} locked before it could reach the server`);
   const reconnected = Date.now(); await control("blockClient=none");
   if (to === "extension") await worker.evaluate(() => networkRestored?.()).catch(() => {});
   log(`${label}: ${to} locked ${await waitLocked(to, page, reconnected)} ms after reconnecting; operations refused while locked`);
   await unlockRejectingOld(to, page, kind === "passphrase" ? old : null, P);
   await converged(label, added);
   await fresh(); await operations(to); await operations(from);
   log(`${label}: account added while cut off was kept and uploaded; every operation works on both clients`);
  }

  assert.deepEqual(errors, []);
  log("passphrase changes treat the other client's vault and operations exactly like key rotation");
 } finally { await control("blockClient=none").catch(() => {}); await context.close(); await webBrowser.close(); }
})().catch(error => { console.error(`[${label}] FAILED`, error); process.exitCode = 1; });
