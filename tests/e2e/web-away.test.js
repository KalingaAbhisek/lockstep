// Changes made while the web app was not open in its tab (the tab went to another site, or the tab was reopened
// with its saved unlocked session). When the web app opens again it must go straight to the right screen and never
// show a code first:
//   - the extension rotated the recovery key      -> lock screen; the passphrase unlocks it;
//   - the extension changed the passphrase         -> lock screen; the old passphrase is refused, the new one works;
//   - another web app signed in to the account     -> sign-in screen, unlocked key removed.
const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
let P = "web-away-passphrase";
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = () => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Away",email:"a@example.test",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const log = (...values) => console.log(`[${label}]`, ...values);
const control = q => fetch(`${API}/__control?${q}`).then(r => r.json());
const googleStub = "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};";
const visible = (page, id) => page.evaluate(id => { const n = document.getElementById(id); return Boolean(n && !n.classList.contains("hidden") && n.getClientRects().length); }, id);
(async () => {
 await control("reset=1"); await control("perClientSessions=1");
 const context = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-web-away-${Date.now()}`), {
  channel:"chromium", headless:true, ignoreDefaultArgs:["--disable-extensions"],
  args:["--headless=new", `--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`] });
 const otherBrowser = await chromium.launch();
 try {
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:googleStub }));
  await context.route("http://elsewhere.test/**", r => r.fulfill({ contentType:"text/html", body:"<!doctype html><title>Elsewhere</title>" }));
  // Records whether a six-digit code was ever on screen in the page.
  await context.addInitScript(() => {
   globalThis.__codeSeen = false; globalThis.__probe = true;
   new MutationObserver(() => { if ([...document.querySelectorAll("#entries .entry .code")].some(n => /\d{3}\s?\d{3}/.test(n.textContent))) globalThis.__codeSeen = true; })
    .observe(document, { subtree: true, childList: true, characterData: true });
  });
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const extensionId = worker.url().split("/")[2];
  const errors = [];
  const web = await context.newPage(); web.on("pageerror", e => errors.push(`web: ${e.message}`));
  await web.goto(WEB); await web.waitForTimeout(500);
  await web.evaluate(t => onGoogleCredential({ credential: t }), token());
  await web.waitForSelector("#lock-dialog[open]");
  await web.fill("#lock-passcode", P); await web.fill("#lock-confirm", P); await web.click('#lock-form button[type="submit"]');
  await web.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await web.evaluate(() => importUris(["otpauth://totp/Alpha:a?secret=JBSWY3DPEHPK3PXP&issuer=Alpha"]));
  await worker.evaluate(async ({ t, P }) => {
   await chrome.storage.local.set({ vaultSubject:"user-1", vaultDisplayName:"Away" });
   await chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() });
   await registerAppSession(); await getLockConfig(); await verifyLock(P); await synchronize();
  }, { t: token(), P });
  const popup = await context.newPage(); popup.on("pageerror", e => errors.push(`popup: ${e.message}`));
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  await popup.waitForSelector("#entries .entry:not(.entry-skel)");
  const freshPopup = () => worker.evaluate(async t => chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() }), token());

  // The web tab leaves; it keeps its saved unlocked session (sessionStorage) for when it comes back.
  async function leave() {
   assert.equal(await web.evaluate(() => Object.keys(sessionStorage).some(k => k.startsWith("authsync.session-key."))), true, "the web app has no saved unlocked session");
   await web.goto("http://elsewhere.test/");
  }
  async function comeBack() {
   await web.goto(WEB);
   assert.equal(await web.evaluate(() => globalThis.__probe), true, "the code probe did not run");
   await web.waitForFunction(() => ["unlock-form", "signed-out"].some(id => { const n = document.getElementById(id); return n && !n.classList.contains("hidden") && n.getClientRects().length; })
    || document.querySelectorAll("#entries .entry:not(.entry-skel)").length > 0, null, { timeout: 10000 });
   await web.waitForTimeout(1500);
   const screen = (await visible(web, "signed-out")) ? "signed-out" : (await visible(web, "unlock-form")) ? "locked" : "codes";
   return { screen, codeSeen: await web.evaluate(() => globalThis.__codeSeen) };
  }
  async function unlock(passphrase) {
   await web.evaluate(() => { document.getElementById("unlock-error").textContent = ""; });
   await web.fill("#unlock-passcode", passphrase); await web.click('#unlock-form button[type="submit"]');
   await web.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length > 0 && !document.getElementById("signed-in").classList.contains("hidden")
    || document.getElementById("unlock-error").textContent.trim(), null, { timeout: 15000 });
   return (await web.textContent("#unlock-error")).trim() || "unlocked";
  }

  // 0. Nothing changed while away: the web app reopens its vault at once (the saved session still works).
  await leave(); let back = await comeBack();
  assert.equal(back.screen, "codes", `with nothing changed the web app reopened to: ${back.screen}`);

  // 1. The extension rotates the recovery key while the web app is away.
  await leave();
  await freshPopup(); await popup.click("#settings"); await popup.waitForTimeout(400); await popup.click("#settings-key-rotate");
  await popup.waitForSelector("#confirm-dialog[open]"); await popup.fill("#confirm-passkey", P); await popup.click("#confirm-accept");
  await popup.waitForFunction(() => /rotated to version/.test(document.getElementById("settings-message").textContent), null, { timeout: 30000 });
  await popup.click("#settings-back"); await popup.waitForTimeout(400);
  back = await comeBack();
  assert.equal(back.screen, "locked", `after a rotation in the extension the web app reopened to: ${back.screen}`);
  assert.equal(back.codeSeen, false, "the web app showed a code before locking after a rotation in the extension");
  assert.equal(await unlock(P), "unlocked");
  log("rotation in the extension while the web app was away: it reopened locked (no code shown) and unlocked with the passphrase");

  // 2. The extension changes the passphrase while the web app is away.
  const old = P; P = "web-away-passphrase-2";
  await leave();
  await freshPopup(); await popup.click("#settings"); await popup.waitForTimeout(400); await popup.click("#settings-lock");
  await popup.fill("#lock-passcode", P); await popup.fill("#lock-confirm", P); await popup.click('#lock-form button[type="submit"]');
  await popup.waitForFunction(() => /Lock protection saved/.test(document.getElementById("settings-message").textContent), null, { timeout: 30000 });
  back = await comeBack();
  assert.equal(back.screen, "locked", `after a passphrase change in the extension the web app reopened to: ${back.screen}`);
  assert.equal(back.codeSeen, false, "the web app showed a code before locking after a passphrase change in the extension");
  assert.match(await unlock(old), /Incorrect passphrase/, "the web app accepted the previous passphrase");
  assert.equal(await unlock(P), "unlocked", "the web app refused the new passphrase");
  log("passphrase change in the extension while the web app was away: it reopened locked, refused the old passphrase, accepted the new one");

  // 3. Another web app signs in while this one is away.
  await leave();
  const deviceB = await otherBrowser.newContext(); await deviceB.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:googleStub }));
  const webB = await deviceB.newPage(); await webB.goto(WEB); await webB.waitForTimeout(500);
  await webB.evaluate(t => onGoogleCredential({ credential: t }), token());
  await webB.waitForTimeout(1000);
  back = await comeBack();
  assert.equal(back.screen, "signed-out", `after another web sign-in the web app reopened to: ${back.screen}`);
  assert.equal(back.codeSeen, false, "the replaced web app showed a code");
  assert.equal(await web.evaluate(() => LockstepVault.isUnlocked("user-1") || Object.keys(sessionStorage).some(k => k.startsWith("authsync.session-key."))), false, "the replaced web app kept its unlocked key");
  log("another web app signed in while this one was away: it reopened signed out (no code shown), key removed");
  assert.equal(await worker.evaluate(async () => { await api("/api/v1/session"); return true; }), true, "the extension was affected");
  assert.deepEqual(errors, []);
 } finally { await context.close(); await otherBrowser.close(); }
})().catch(error => { console.error(`[${label}] FAILED`, error); process.exitCode = 1; });
