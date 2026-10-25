// Offline additions and retries. A scanned account added while the device is offline shows its code at once and
// is uploaded as soon as the device is back online. While online but the server is unreachable, uploads are
// retried every 5 to 10 seconds (no growing backoff), so a change arrives within about 10 s of the server
// recovering, with no duplicates. Checked for the web app and the extension.
const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
const P = "offline-retry-passphrase";
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = () => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Offline",email:"o@example.test",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const uri = (name, secret) => `otpauth://totp/${name}:o?secret=${secret}&issuer=${name}`;
const log = (...values) => console.log(`[${label}]`, ...values);
const control = q => fetch(`${API}/__control?${q}`).then(r => r.json());
const serverCount = async () => (await control("")).entries.length;
async function until(check, timeout, what) {
 const started = Date.now();
 while (!(await check())) { if (Date.now() - started > timeout) throw Error(`${what} did not happen within ${timeout} ms`); await new Promise(r => setTimeout(r, 100)); }
 return Date.now() - started;
}
(async () => {
 await control("reset=1");
 const context = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-offline-retry-${Date.now()}`), {
  channel:"chromium", headless:true, ignoreDefaultArgs:["--disable-extensions"],
  args:["--headless=new", `--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`] });
 try {
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:"window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const errors = [];
  const web = await context.newPage(); web.on("pageerror", e => errors.push(`web: ${e.message}`));
  await web.goto(WEB); await web.waitForTimeout(500);
  await web.evaluate(t => onGoogleCredential({ credential: t }), token());
  await web.waitForSelector("#lock-dialog[open]");
  await web.fill("#lock-passcode", P); await web.fill("#lock-confirm", P); await web.click('#lock-form button[type="submit"]');
  await web.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await web.evaluate(u => importUris([u]), uri("Existing", "JBSWY3DPEHPK3PXP"));
  await until(async () => await serverCount() === 1, 10000, "initial upload");

  // 1. Web app offline: a scanned account shows its code at once and is uploaded as soon as the device is online.
  await web.setViewportSize({ width: 900, height: 800 });
  await context.setOffline(true); await web.evaluate(() => window.dispatchEvent(new Event("offline")));
  await web.evaluate(u => handleCameraResult(u), uri("Scanned offline", "GEZDGNBVGY3TQOJQ"));
  await web.waitForFunction(() => [...document.querySelectorAll("#entries .entry")].some(n => n.querySelector(".issuer")?.textContent === "Scanned offline" && /\d{3} \d{3}/.test(n.querySelector(".code")?.textContent || "")), null, { timeout: 5000 });
  assert.equal(await web.evaluate(() => LockstepVault.pendingCount("user-1")), 1, "the offline addition is not queued");
  assert.equal(await serverCount(), 1, "an addition reached the server while offline");
  const summary = (await web.textContent("#account-summary")).trim();
  assert.match(summary, /Offline/, `the summary does not say the device is offline: ${summary}`);
  await context.setOffline(false);
  const onlineAt = Date.now(); await web.evaluate(() => window.dispatchEvent(new Event("online")));
  await until(async () => await serverCount() === 2, 5000, "upload after reconnecting");
  log(`web: account scanned offline showed its code at once; uploaded ${Date.now() - onlineAt} ms after the device came online ("${summary}")`);

  // 2. Web app online, server unreachable: the queued change is retried every 5-10 s and arrives soon after recovery.
  await control("down=1");
  await web.evaluate(u => addOtpUri(u).catch(() => null), uri("While server down", "MFRGGZDFMZTWQ2LK"));
  assert.equal(await web.evaluate(() => LockstepVault.pendingCount("user-1")), 1, "the change is not queued while the server is down");
  await web.waitForTimeout(12000); // several failed attempts
  await control("down=0");
  const webRecovery = await until(async () => await serverCount() === 3, 12000, "web retry after the server recovered");
  assert(webRecovery <= 11000, `the web app retried too late: ${webRecovery} ms`);
  log(`web: change made while the server was down arrived ${webRecovery} ms after it recovered`);

  // 3. Extension: the same with the popup closed (background worker only).
  await worker.evaluate(async ({ t, P }) => {
   await chrome.storage.local.set({ vaultSubject:"user-1", vaultDisplayName:"Offline", appSessionId:"session-token", appSessionExpiry:Date.now()+864e5 });
   await chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() });
   await getLockConfig(); await verifyLock(P); await synchronize();
  }, { t: token(), P });
  await control("down=1");
  await worker.evaluate(u => addOtpUri(u).catch(() => null), uri("Extension while down", "ONSWG4TFOQYTEMZU"));
  assert.equal(await worker.evaluate(() => LockstepVault.pendingCount("user-1")), 1, "the extension did not queue the change");
  const shown = await worker.evaluate(async () => (await localEntries()).find(e => e.issuer === "Extension while down")?.code);
  assert.match(String(shown), /^\d{6}$/, "the extension does not show the code of an account added while the server is down");
  await web.waitForTimeout(12000);
  await control("down=0");
  const extRecovery = await until(async () => await serverCount() === 4, 12000, "extension retry after the server recovered");
  assert(extRecovery <= 11000, `the extension retried too late: ${extRecovery} ms`);
  log(`extension: change made while the server was down arrived ${extRecovery} ms after it recovered (popup closed)`);

  // 4. Extension scanner while offline: select a QR code in a web page, the account is added and shows its code at
  //    once, the page shows Lockstep's own notice (never a blocking alert), and the account uploads when online.
  //    The real scanner.js and jsQR run in the page; only Chrome's capture/messaging plumbing is provided by the test
  //    (headless Chrome cannot grant the activeTab permission that the toolbar click gives).
  {
   const fs = require("node:fs");
   const scanUri = uri("Scanned in tab", "KRSXG5BAMFZGK3TP");
   await context.route("http://scan.test/**", r => r.fulfill({ contentType: "text/html", body: "<!doctype html><body style='margin:0;background:#fff'><p style='font:16px sans-serif;margin:20px'>Set up your authenticator</p><img id=qr style='margin:20px'></body>" }));
   const tab = await context.newPage(); await tab.setViewportSize({ width: 800, height: 600 });
   const dialogs = []; tab.on("dialog", d => { dialogs.push(d.message()); d.dismiss(); });
   await tab.goto("http://scan.test/");
   await tab.addScriptTag({ content: fs.readFileSync(path.join(extensionDir, "vendor/qrcode.js"), "utf8") });
   await tab.evaluate(async u => { document.getElementById("qr").src = await QRCode.toDataURL(u, { margin: 2, width: 260 }); await new Promise(r => setTimeout(r, 200)); }, scanUri);
   await tab.exposeFunction("__lockstepAdd", u => worker.evaluate(u => addOtpUri(u).then(entry => ({ ok: true, data: { id: entry.id } }), e => ({ ok: false, error: e.message })), u));
   await tab.evaluate(() => { globalThis.chrome = { runtime: { onMessage: { addListener() {} }, sendMessage: async m => m.type === "ADD_OTP_URI" ? globalThis.__lockstepAdd(m.otpAuthUri) : { ok: false } } }; });
   await tab.addScriptTag({ content: fs.readFileSync(path.join(extensionDir, "vendor/jsQR.js"), "utf8") });
   await tab.addScriptTag({ content: fs.readFileSync(path.join(extensionDir, "scanner.js"), "utf8") });
   const screenshot = `data:image/png;base64,${(await tab.screenshot()).toString("base64")}`;
   await context.setOffline(true); await control("down=1");
   await tab.evaluate(s => selectAndScan(s), screenshot);
   const box = await tab.locator("#qr").boundingBox();
   await tab.mouse.move(box.x - 8, box.y - 8); await tab.mouse.down();
   await tab.mouse.move(box.x + box.width / 2, box.y + box.height / 2, { steps: 4 });
   await tab.mouse.move(box.x + box.width + 8, box.y + box.height + 8, { steps: 4 }); await tab.mouse.up();
   const before = await serverCount();
   const added = await worker.evaluate(async () => {
    for (let i = 0; i < 60; i++) { const e = (await localEntries()).find(x => x.issuer === "Scanned in tab"); if (e) return e.code; await new Promise(r => setTimeout(r, 100)); }
    return null;
   });
   assert.match(String(added), /^\d{6}$/, "the scanned account does not show a code while offline");
   const notice = await tab.waitForFunction(() => globalThis.__authsyncScanResult && document.documentElement.contains(globalThis.__authsyncScanResult), null, { timeout: 5000 }).then(() => true, () => false);
   assert(notice, "the scanner showed no result notice");
   assert.deepEqual(dialogs, [], `the scanner used a blocking browser dialog: ${dialogs}`);
   assert.equal(await serverCount(), before, "the scanned account reached the server while offline");
   await control("down=0"); await context.setOffline(false);
   const reconnected = Date.now(); await worker.evaluate(() => networkRestored());
   await until(async () => await serverCount() === before + 1, 12000, "upload of the account scanned offline");
   log(`extension: QR selected in a tab while offline showed code ${added} at once (in-page notice, no alert); uploaded ${Date.now() - reconnected} ms after reconnecting`);
   await tab.close();
  }

  // No duplicates anywhere.
  const expected = JSON.stringify(["Existing", "Extension while down", "Scanned in tab", "Scanned offline", "While server down"]);
  const webNames = async () => JSON.stringify((await web.evaluate(async () => { await syncVault().catch(() => null); return (await LockstepVault.listEntries("user-1")).map(e => e.issuer); })).sort());
  await until(async () => await webNames() === expected, 10000, `web app list ${await webNames()}`);
  const extNames = JSON.stringify((await worker.evaluate(async () => { await synchronize(); return (await localEntries()).map(e => e.issuer); })).sort());
  assert.equal(extNames, expected, "the extension's list differs");
  assert.equal(await serverCount(), 5, "duplicates on the server");
  assert.deepEqual(errors, []);
  log("no duplicates; all clients agree");
 } finally { await context.close(); }
})().catch(error => { console.error(`[${label}] FAILED`, error); process.exitCode = 1; });
