// "Reset vault" for someone who lost both the passphrase and the recovery key, in the web app and in the extension,
// on the usual device and on a brand-new one: no passphrase is asked; the button works only once RESET is typed
// (a wrong word or a cancel deletes nothing); a stale Google sign-in must be confirmed first; afterwards the
// vault is gone from the server and both clients, and a new vault can be created.
const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = () => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Reset",email:"k@example.test",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const uri = (name, n) => `otpauth://totp/${encodeURIComponent(name)}:k?secret=${Array.from({length:16},(_, i)=>B32[(n*3+i*11)%32]).join("")}&issuer=${encodeURIComponent(name)}`;
const log = (...values) => console.log(`[${label}]`, ...values);
const control = q => fetch(`${API}/__control?${q}`).then(r => r.json());
const googleStub = "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};";
(async () => {
 await control("reset=1");
 const context = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-reset-${Date.now()}`), {
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
   await chrome.storage.local.set({ vaultSubject:"user-1", vaultDisplayName:"Reset", appSessionId:"session-token", appSessionExpiry:Date.now()+864e5 });
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
  const state = () => control("");
  // Opens the reset dialog from the restore screen and checks the typed-word gate; returns the page ready to type.
  async function openReset(who, page) {
   await page.click("#restore-reset"); await page.waitForSelector("#confirm-dialog[open]", { timeout: 5000 });
   const ui = await page.evaluate(() => { const i = document.getElementById("confirm-passkey"); return { type: i.type, placeholder: i.placeholder, visible: !i.classList.contains("hidden"), disabled: document.getElementById("confirm-accept").disabled, message: document.getElementById("confirm-message").textContent }; });
   assert(ui.visible && ui.type === "text" && /Type RESET/.test(ui.placeholder), `${who}: the dialog does not ask to type RESET (${JSON.stringify(ui)})`);
   assert(!/passphrase/i.test(ui.message), `${who}: the reset dialog still asks for the passphrase`);
   assert(ui.disabled, `${who}: Reset is enabled before RESET is typed`);
   for (const [word, enabled] of [["RESE", false], ["passphrase-guess", false], ["reset", true], ["RESET", true]]) {
    await page.fill("#confirm-passkey", word);
    assert.equal(!await page.evaluate(() => document.getElementById("confirm-accept").disabled), enabled, `${who}: typing "${word}" ${enabled ? "did not enable" : "enabled"} Reset`);
   }
  }
  async function cancelDeletesNothing(who, page) {
   await openReset(who, page); await page.fill("#confirm-passkey", "RESE"); await page.keyboard.press("Enter"); await page.waitForTimeout(300);
   assert(await page.evaluate(() => document.getElementById("confirm-dialog").open), `${who}: Enter with a wrong word closed the dialog`);
   await page.click("#confirm-cancel"); await page.waitForTimeout(800);
   assert((await state()).exists && (await state()).resets === 0, `${who}: cancelling deleted the vault`);
  }
  async function setup(passphrase) {
   await web.goto(WEB); await web.waitForTimeout(500);
   await web.evaluate(t => onGoogleCredential({ credential: t }), token());
   await web.waitForSelector("#lock-dialog[open]", { timeout: 15000 });
   await web.fill("#lock-passcode", passphrase); await web.fill("#lock-confirm", passphrase); await web.click('#lock-form button[type="submit"]');
   await web.waitForFunction(() => !document.getElementById("lock-dialog").open, null, { timeout: 30000 });
   await web.evaluate(us => importUris(us), [uri("Alpha", 1), uri("Bravo", 2)]);
   await web.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 2, null, { timeout: 15000 });
  }

  // 1. Web app, usual device, passphrase forgotten, Google sign-in stale: confirm with Google, then reset.
  await web.click("#lock-now"); await web.waitForSelector("#locked:not(.hidden)");
  await web.click("#forgot-passkey"); await web.waitForSelector("#restore:not(.hidden)");
  await cancelDeletesNothing("web", web);
  await openReset("web", web); await web.fill("#confirm-passkey", "RESET");
  const stale = `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Reset",email:"r@example.test",iat:Math.floor(Date.now()/1000)-900,exp:Math.floor(Date.now()/1000)+3600})}.sig`;
  await web.evaluate(t => { state.token = t; sessionStorage.setItem("authsync.idToken", t); }, stale);
  await web.click("#confirm-accept");
  await web.waitForSelector("#reauth-dialog[open]", { timeout: 10000 });
  assert((await state()).exists, "web: the vault was deleted before Google confirmation");
  await web.evaluate(t => onGoogleCredential({ credential: t }), token());
  await web.waitForSelector("#signed-out:not(.hidden)", { timeout: 15000 });
  let st = await state(); assert(!st.exists && st.resets === 1 && st.entries.length === 0, "web: the vault was not deleted");
  assert.equal(await web.evaluate(async () => (await LockstepVault.localEncryptedEntries("user-1")).length), 0, "web: accounts left on the device");
  // The extension is signed out at once (the reset ends every session) and shows no codes; its encrypted copy
  // is removed as soon as it signs in again and learns the vault is gone.
  await popup.waitForSelector("#signed-out:not(.hidden)", { timeout: 20000 });
  assert.equal(await popup.evaluate(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length), 0, "extension: codes still shown after the reset");
  await worker.evaluate(header => {
   AUTHSYNC_CONFIG.googleClientId = "test-client.apps.googleusercontent.com";
   chrome.identity.launchWebAuthFlow = async ({ url }) => {
    const nonce = new URL(url).searchParams.get("nonce"), now = Math.floor(Date.now()/1000);
    const body = btoa(JSON.stringify({sub:"user-1",name:"Reset",email:"r@example.test",nonce,iat:now,exp:now+3600})).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
    return `${chrome.identity.getRedirectURL("google")}#id_token=${header}.${body}.sig`;
   };
  }, b64({alg:"RS256"}));
  await popup.click("#login");
  await popup.waitForFunction(() => !document.getElementById("signed-out").classList.contains("hidden") ? false : true, null, { timeout: 15000 });
  await popup.waitForTimeout(4000);
  assert(!await visible(popup, "locked"), "extension: asked to unlock the deleted vault after signing in again");
  assert.equal(await worker.evaluate(async () => (await LockstepVault.localEncryptedEntries("user-1")).length), 0, "extension: the deleted vault's accounts were kept after signing in again");
  log("web reset without the passphrase: RESET required, Google confirmed, vault gone from server and both clients");

  // 2. A new vault can be created afterwards.
  await setup("reset-passphrase-two");
  log("a new vault was created after the reset");

  // 3. Extension on a brand-new device (new profile, nothing stored), passphrase unknown.
  const ctx2 = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-reset2-${Date.now()}`), { channel:"chromium", headless:true, ignoreDefaultArgs:["--disable-extensions"], args:["--headless=new", `--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`] });
  try {
   let [w2] = ctx2.serviceWorkers(); if (!w2) w2 = await ctx2.waitForEvent("serviceworker");
   await w2.evaluate(async t => { await chrome.storage.local.set({ vaultSubject:"user-1", vaultDisplayName:"Reset" }); await chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() }); await registerAppSession(); await getLockConfig().catch(() => {}); }, token());
   const pop2 = await ctx2.newPage(); pop2.on("pageerror", e => errors.push(`popup2: ${e.message}`));
   await pop2.goto(`chrome-extension://${w2.url().split("/")[2]}/popup.html`);
   await pop2.waitForSelector("#locked:not(.hidden), #restore:not(.hidden)", { timeout: 15000 });
   if (await visible(pop2, "locked")) { await pop2.click("#forgot-passkey"); await pop2.waitForSelector("#restore:not(.hidden)"); }
   const before = (await state()).resets;
   await cancelDeletesNothing("extension (new device)", pop2).catch(e => { if (!/resets === 0|cancelling/.test(e.message)) throw e; });
   assert.equal((await state()).resets, before, "extension: cancelling deleted the vault");
   assert.equal((await w2.evaluate(() => resetVault("passphrase-guess").then(() => "deleted", e => e.message))).slice(0, 10), "Type RESET", "extension worker accepted a reset without RESET");
   await openReset("extension (new device)", pop2); await pop2.fill("#confirm-passkey", "RESET"); await pop2.click("#confirm-accept");
   await pop2.waitForSelector("#signed-out:not(.hidden)", { timeout: 15000 });
   st = await state(); assert(!st.exists && st.resets === before + 1 && st.entries.length === 0, "extension: the vault was not deleted");
   // The web app (which had the vault open) does not keep it.
   await web.waitForSelector("#signed-out:not(.hidden), #lock-dialog[open]", { timeout: 20000 });
   log("extension reset on a new device without the passphrase: RESET required, vault gone, web app followed");
  } finally { await ctx2.close(); }

  assert.deepEqual(errors, []);
  log("reset vault works without the passphrase in both clients, only after typing RESET and confirming with Google");
 } finally { await context.close(); await webBrowser.close(); }
})().catch(error => { console.error(`[${label}] FAILED`, error); process.exitCode = 1; });
