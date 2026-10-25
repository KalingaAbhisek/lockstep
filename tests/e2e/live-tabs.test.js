// Several web app tabs and the extension popup open at once for the same Google account. The API allows only a
// few live connections per account, so the web app's tabs must share one connection (one tab listens and tells
// the others) and the popup must never be shut out: every change still reaches every tab and the popup at once,
// another tab takes over when the listening tab closes, and a sign-in elsewhere signs out every tab.
const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
const P = "live-tabs-passphrase";
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = () => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Tabs",email:"t@example.test",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const uri = name => `otpauth://totp/${name}:t?secret=JBSWY3DPEHPK3PXP&issuer=${encodeURIComponent(name)}`;
const log = (...values) => console.log(`[${label}]`, ...values);
const control = q => fetch(`${API}/__control?${q}`).then(r => r.json());
const googleStub = "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};";
// NO_SHARE=1: web app tabs that cannot share a connection (a browser without BroadcastChannel, or an older
// cached copy of the web app): each tab connects itself, and the API must still make room for the popup.
const NO_SHARE = process.env.NO_SHARE === "1";
const shows = (page, name, timeout = 3000) => page.waitForFunction(n => [...document.querySelectorAll("#entries .issuer")].some(e => e.textContent === n), name, { timeout });
(async () => {
 await control("reset=1"); await control("perClientSessions=1");
 const context = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-live-tabs-${Date.now()}`), {
  channel:"chromium", headless:true, ignoreDefaultArgs:["--disable-extensions"],
  args:["--headless=new", `--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`] });
 const otherBrowser = await chromium.launch();
 try {
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:googleStub }));
  if (NO_SHARE) await context.addInitScript(() => { delete globalThis.BroadcastChannel; });
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const extensionId = worker.url().split("/")[2];
  const errors = [];
  const tabs = [];
  const first = await context.newPage(); first.on("pageerror", e => errors.push(`tab0: ${e.message}`)); tabs.push(first);
  await first.goto(WEB); await first.waitForTimeout(500);
  await first.evaluate(t => onGoogleCredential({ credential: t }), token());
  await first.waitForSelector("#lock-dialog[open]");
  await first.fill("#lock-passcode", P); await first.fill("#lock-confirm", P); await first.click('#lock-form button[type="submit"]');
  await first.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await first.evaluate(u => importUris([u]), uri("Alpha"));
  // Three more tabs of the web app in the same browser, each unlocked.
  for (let i = 1; i < 4; i++) {
   const tab = await context.newPage(); tab.on("pageerror", e => errors.push(`tab${i}: ${e.message}`)); tabs.push(tab);
   await tab.goto(WEB);
   await tab.waitForSelector("#unlock-form", { state: "visible", timeout: 10000 });
   await tab.fill("#unlock-passcode", P); await tab.click('#unlock-form button[type="submit"]');
   await shows(tab, "Alpha", 15000);
  }
  // The extension signs in (its own session) and its popup opens last, after all four tabs.
  await worker.evaluate(async ({ t, P }) => {
   await chrome.storage.local.set({ vaultSubject:"user-1", vaultDisplayName:"Tabs" });
   await chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() });
   await registerAppSession(); await getLockConfig(); await verifyLock(P); await synchronize();
  }, { t: token(), P });
  const popup = await context.newPage(); popup.on("pageerror", e => errors.push(`popup: ${e.message}`));
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  await shows(popup, "Alpha", 10000);
  await popup.waitForTimeout(2500); // every client has had time to open its live connection
  const connections = (await control("")).liveConnections;
  log(`4 web tabs + popup hold ${connections} live connection(s)`);

  // 1. A change in a web tab reaches the popup at once.
  let started = Date.now();
  await tabs[2].evaluate(u => importUris([u]), uri("From web"));
  await shows(popup, "From web");
  log(`web tab -> popup: ${Date.now() - started} ms`);

  // 2. A change in the extension reaches every web tab at once (not only the one holding the connection).
  started = Date.now();
  await worker.evaluate(u => addOtpUri(u), uri("From extension"));
  if (NO_SHARE) {
   // Five clients for four places: the web tabs take turns (each reconnects and catches up), the popup stays.
   await Promise.all(tabs.map(tab => shows(tab, "From extension", 40000)));
   log(`extension -> all 4 web tabs (taking turns): ${Date.now() - started} ms`);
   started = Date.now();
   await tabs[1].evaluate(u => importUris([u]), uri("Second from web"));
   await shows(popup, "Second from web");
   log(`popup still live while the tabs take turns: ${Date.now() - started} ms`);
   assert.deepEqual(errors, []);
   return;
  }
  await Promise.all(tabs.map(tab => shows(tab, "From extension")));
  log(`extension -> all 4 web tabs: ${Date.now() - started} ms`);
  assert(connections <= 2, `the web app's tabs should share one live connection; ${connections} are open`);

  // 3. The tabs that are listening close: the remaining tab takes over and still gets changes at once.
  await Promise.all(tabs.slice(0, 3).map(tab => tab.close())); const last = tabs[3];
  await last.waitForTimeout(1500);
  started = Date.now();
  await worker.evaluate(u => addOtpUri(u), uri("After closing"));
  await shows(last, "After closing");
  log(`after closing 3 tabs, the remaining tab still updated in ${Date.now() - started} ms`);

  // 4. A second web tab opened again, then a web sign-in on another device signs out both tabs at once
  //    (keys cleared); the popup keeps working.
  const again = await context.newPage(); again.on("pageerror", e => errors.push(`again: ${e.message}`));
  await again.goto(WEB); await again.waitForSelector("#unlock-form", { state: "visible", timeout: 10000 });
  await again.fill("#unlock-passcode", P); await again.click('#unlock-form button[type="submit"]');
  await shows(again, "After closing", 15000); await again.waitForTimeout(1500);
  const deviceB = await otherBrowser.newContext(); await deviceB.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:googleStub }));
  const webB = await deviceB.newPage(); await webB.goto(WEB); await webB.waitForTimeout(500);
  started = Date.now();
  await webB.evaluate(t => onGoogleCredential({ credential: t }), token());
  for (const tab of [last, again]) {
   await tab.waitForSelector("#signed-out:not(.hidden)", { timeout: 3000 });
   assert.equal(await tab.evaluate(() => LockstepVault.isUnlocked("user-1")), false, "a replaced tab kept its unlocked key");
  }
  log(`sign-in on another device signed out both tabs in ${Date.now() - started} ms`);
  await popup.waitForTimeout(500);
  assert.equal(await popup.evaluate(() => isAuthenticated), true, "the popup was signed out by a web sign-in");
  assert.deepEqual(errors, []);
 } finally { await context.close(); await otherBrowser.close(); }
})().catch(error => { console.error(`[${label}] FAILED`, error); process.exitCode = 1; });
