// Changes made while the extension popup is closed (its background worker has no live connection then). When the
// popup next opens it must go straight to the right screen and never show a code first:
//   - the web app rotated the recovery key      -> lock screen; the passphrase unlocks it;
//   - the web app changed the passphrase         -> lock screen; the old passphrase is refused, the new one works;
//   - another extension signed in to the account -> sign-in screen, unlocked key removed.
const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
let P = "popup-closed-passphrase";
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = () => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Closed",email:"c@example.test",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const log = (...values) => console.log(`[${label}]`, ...values);
const control = q => fetch(`${API}/__control?${q}`).then(r => r.json());
const googleStub = "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};";
const visible = (page, id) => page.evaluate(id => { const n = document.getElementById(id); return Boolean(n && !n.classList.contains("hidden") && n.getClientRects().length); }, id);
(async () => {
 await control("reset=1"); await control("perClientSessions=1");
 const context = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-popup-closed-${Date.now()}`), {
  channel:"chromium", headless:true, ignoreDefaultArgs:["--disable-extensions"],
  args:["--headless=new", `--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`] });
 try {
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:googleStub }));
  // Records, in every page, whether a six-digit code was ever on screen.
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
  await web.evaluate(() => importUris(["otpauth://totp/Alpha:c?secret=JBSWY3DPEHPK3PXP&issuer=Alpha"]));
  await worker.evaluate(async ({ t, P }) => {
   await chrome.storage.local.set({ vaultSubject:"user-1", vaultDisplayName:"Closed" });
   await chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() });
   await registerAppSession(); await getLockConfig(); await verifyLock(P); await synchronize();
  }, { t: token(), P });
  assert.equal(await worker.evaluate(() => LockstepVault.isUnlocked("user-1")), true);

  // Opens the popup and waits until it settles on one screen; reports the screen and whether a code was shown.
  async function openPopup() {
   const popup = await context.newPage(); popup.on("pageerror", e => errors.push(`popup: ${e.message}`));
   await popup.goto(`chrome-extension://${extensionId}/popup.html`);
   assert.equal(await popup.evaluate(() => globalThis.__probe), true, "the code probe did not run in the popup");
   await popup.waitForFunction(() => ["unlock-form", "signed-out"].some(id => { const n = document.getElementById(id); return n && !n.classList.contains("hidden") && n.getClientRects().length; })
    || document.querySelectorAll("#entries .entry:not(.entry-skel)").length > 0, null, { timeout: 10000 });
   await popup.waitForTimeout(1500); // anything that would still change the screen happens now
   const screen = (await visible(popup, "signed-out")) ? "signed-out" : (await visible(popup, "unlock-form")) ? "locked" : "codes";
   return { popup, screen, codeSeen: await popup.evaluate(() => globalThis.__codeSeen) };
  }
  async function unlock(popup, passphrase) {
   await popup.evaluate(() => { const e = document.getElementById("unlock-error"); e.textContent = ""; });
   await popup.fill("#unlock-passcode", passphrase); await popup.click('#unlock-form button[type="submit"]');
   await popup.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length > 0 && !document.getElementById("signed-in").classList.contains("hidden")
    || document.getElementById("unlock-error").textContent.trim(), null, { timeout: 15000 });
   return (await popup.textContent("#unlock-error")).trim() || "unlocked";
  }

  // 1. The web app rotates the recovery key while the popup is closed.
  await web.click("#open-settings"); await web.click("#settings-key-rotate");
  await web.waitForSelector("#confirm-dialog[open]"); await web.fill("#confirm-passkey", P); await web.click("#confirm-accept");
  await web.waitForFunction(() => /rotated to version/.test(document.getElementById("toast").textContent), null, { timeout: 30000 });
  let opened = await openPopup();
  assert.equal(opened.screen, "locked", `after a rotation elsewhere the popup opened to: ${opened.screen}`);
  assert.equal(opened.codeSeen, false, "the popup showed a code before locking after a rotation elsewhere");
  assert.equal(await unlock(opened.popup, P), "unlocked");
  await opened.popup.close();
  log("rotation in the web app while the popup was closed: popup opened locked (no code shown) and unlocked with the passphrase");

  // 2. The web app changes the passphrase while the popup is closed.
  const old = P; P = "popup-closed-passphrase-2";
  await web.waitForTimeout(500); await web.evaluate(() => document.getElementById("toast").textContent = "");
  await web.click("#open-settings"); await web.click("#settings-lock");
  await web.fill("#lock-passcode", P); await web.fill("#lock-confirm", P); await web.click('#lock-form button[type="submit"]');
  await web.waitForFunction(() => !document.getElementById("lock-dialog").open, null, { timeout: 30000 });
  opened = await openPopup();
  assert.equal(opened.screen, "locked", `after a passphrase change elsewhere the popup opened to: ${opened.screen}`);
  assert.equal(opened.codeSeen, false, "the popup showed a code before locking after a passphrase change elsewhere");
  assert.match(await unlock(opened.popup, old), /Incorrect passphrase/, "the popup accepted the previous passphrase");
  assert.equal(await unlock(opened.popup, P), "unlocked", "the popup refused the new passphrase");
  await opened.popup.close();
  log("passphrase change in the web app while the popup was closed: popup opened locked, refused the old passphrase, accepted the new one");

  // 3. Another extension signs in while the popup is closed.
  const other = await fetch(`${API}/api/v1/session`, { method:"POST", headers:{ Authorization:`Bearer ${token()}`, "X-Lockstep-Client":"extension" } });
  assert.equal(other.status, 200);
  opened = await openPopup();
  assert.equal(opened.screen, "signed-out", `after another extension signed in the popup opened to: ${opened.screen}`);
  assert.equal(opened.codeSeen, false, "the replaced extension showed a code");
  assert.equal(await worker.evaluate(async () => LockstepVault.isUnlocked("user-1") || Boolean((await chrome.storage.session.get("unlockedMaster")).unlockedMaster)), false, "the replaced extension kept its unlocked key");
  log("another extension signed in while the popup was closed: popup opened signed out (no code shown), key removed");
  assert.equal(await web.evaluate(() => api("/api/v1/session").then(() => true, () => false)), true, "the web app was affected");
  assert.deepEqual(errors, []);
 } finally { await context.close(); }
})().catch(error => { console.error(`[${label}] FAILED`, error); process.exitCode = 1; });
