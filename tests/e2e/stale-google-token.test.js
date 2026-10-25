// In real use Google's sign-in token expires after an hour, while the Lockstep session lasts 30 days; the clients
// keep working on the Lockstep session alone. With an expired Google token in the extension (and in the web app):
//   - the web app changes the passphrase -> the extension locks and stays on the lock screen (never "sign in
//     with Google"), refuses the old passphrase, accepts the new one, and every operation works;
//   - the extension changes the passphrase -> the web app does the same;
//   - the same for a recovery-key rotation in each direction.
const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
// A Google token issued 2 hours ago that expired an hour ago, and a fresh one (for the device making the change,
// which confirms with Google as the real app does).
const token = (ageSeconds = 0) => { const iat = Math.floor(Date.now()/1000) - ageSeconds; return `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Stale",email:"s@example.test",iat,exp:iat+3600})}.sig`; };
const log = (...values) => console.log(`[${label}]`, ...values);
const control = q => fetch(`${API}/__control?${q}`).then(r => r.json());
const googleStub = "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};";
const screenOf = page => page.evaluate(() => {
 const shown = id => { const n = document.getElementById(id); return Boolean(n && !n.classList.contains("hidden") && n.getClientRects().length); };
 if (document.getElementById("lock-dialog")?.open) return "setup";
 if (shown("signed-out")) return "signed-out";
 if (shown("unlock-form")) return "unlock";
 if (shown("restore")) return "restore";
 if (shown("signed-in")) return "codes";
 return "loading";
});
async function watchScreens(page, millis) {
 const seen = [], start = Date.now();
 for (const end = Date.now() + millis; Date.now() < end;) {
  const s = await screenOf(page).catch(() => "loading");
  if (seen[seen.length - 1]?.split("@")[0] !== s) seen.push(seen.length ? `${s}@${Date.now() - start}` : s);
  await page.waitForTimeout(50);
 }
 return seen;
}
(async () => {
 await control("reset=1"); await control("perClientSessions=1");
 const context = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-stale-${Date.now()}`), {
  channel:"chromium", headless:true, ignoreDefaultArgs:["--disable-extensions"],
  args:["--headless=new", `--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`] });
 const webBrowser = await chromium.launch(), webContext = await webBrowser.newContext({ acceptDownloads: true });
 try {
  await webContext.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:googleStub }));
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const extensionId = worker.url().split("/")[2];
  // Google's window is never available silently (as when the user's Google session needs a click).
  await worker.evaluate(() => {
   AUTHSYNC_CONFIG.googleClientId = "test-client.apps.googleusercontent.com";
   chrome.identity.launchWebAuthFlow = async ({ interactive }) => { throw new Error(interactive ? "The user did not approve access." : "User interaction required."); };
  });
  const errors = [];
  let P = "stale-passphrase-one";
  const web = await webContext.newPage(); web.on("pageerror", e => errors.push(`web: ${e.message}`));
  await web.goto(WEB); await web.waitForTimeout(500);
  await web.evaluate(t => onGoogleCredential({ credential: t }), token());
  await web.waitForSelector("#lock-dialog[open]");
  await web.fill("#lock-passcode", P); await web.fill("#lock-confirm", P); await web.click('#lock-form button[type="submit"]');
  await web.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await web.evaluate(() => importUris(["otpauth://totp/Alpha:s?secret=JBSWY3DPEHPK3PXP&issuer=Alpha"]));
  await worker.evaluate(async ({ t, P }) => {
   await chrome.storage.local.set({ vaultSubject:"user-1", vaultDisplayName:"Stale" });
   await chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() });
   await registerAppSession(); await getLockConfig(); await verifyLock(P); await synchronize();
  }, { t: token(), P });
  // An hour later: both clients' Google tokens have expired; the Lockstep sessions are still valid.
  // NO_GOOGLE_TOKEN=1: no Google token at all (the browser restarted, which clears it; the web app was reloaded).
  const ageClients = async () => {
   if (process.env.NO_GOOGLE_TOKEN === "1") {
    await worker.evaluate(async () => chrome.storage.session.remove(["idToken", "tokenExpiry", "interactiveSignInAt"]));
    await web.evaluate(() => { state.token = null; sessionStorage.removeItem("authsync.idToken"); });
    return;
   }
   await worker.evaluate(async t => chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()-3600e3, interactiveSignInAt:Date.now()-7200e3 }), token(7200));
   await web.evaluate(t => { state.token = t; sessionStorage.setItem("authsync.idToken", t); }, token(7200));
  };
  await ageClients();
  const popup = await context.newPage(); popup.on("pageerror", e => errors.push(`popup: ${e.message}`));
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  await popup.waitForSelector("#entries .entry:not(.entry-skel)", { timeout: 15000 });
  assert.equal(await screenOf(popup), "codes", "the extension did not open with an expired Google token");
  for (const started = Date.now(); (await control("")).liveConnections < 2;) { if (Date.now() - started > 10000) throw Error("live channels did not connect"); await web.waitForTimeout(100); }

  async function unlock(page, passphrase) {
   await page.evaluate(() => { document.getElementById("unlock-error").textContent = ""; });
   await page.fill("#unlock-passcode", passphrase); await page.click('#unlock-form button[type="submit"]');
   await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length > 0 && !document.getElementById("signed-in").classList.contains("hidden")
    || document.getElementById("unlock-error").textContent.trim() || !document.getElementById("signed-out").classList.contains("hidden"), null, { timeout: 15000 });
   if (await screenOf(page) === "signed-out") return "signed-out";
   return (await page.textContent("#unlock-error")).trim() || "unlocked";
  }
  // The device making the change confirms with Google (a fresh token), as the real app asks the user to.
  const freshWeb = () => web.evaluate(t => { state.token = t; sessionStorage.setItem("authsync.idToken", t); }, token());
  const freshExtension = () => worker.evaluate(async t => chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() }), token());
  async function expectLockedOnly(who, page) {
   const screens = await watchScreens(page, 6000);
   log(`${who} screens after the change:`, screens.join(" -> "));
   assert(!screens.some(x => x.startsWith("signed-out")), `${who} went to "sign in with Google" after a change on the other device: ${screens.join(" -> ")}`);
   assert.equal(screens[screens.length - 1].split("@")[0], "unlock", `${who} did not stay on the lock screen: ${screens.join(" -> ")}`);
  }

  // 1. The web app changes the passphrase.
  const old1 = P; P = "stale-passphrase-two";
  await freshWeb(); await web.click("#open-settings"); await web.click("#settings-lock");
  await web.fill("#lock-passcode", P); await web.fill("#lock-confirm", P); await web.click('#lock-form button[type="submit"]');
  await web.waitForFunction(() => !document.getElementById("lock-dialog").open, null, { timeout: 30000 });
  await ageClients();
  await expectLockedOnly("extension", popup);
  assert.match(await unlock(popup, old1), /Incorrect passphrase/, "the extension accepted the old passphrase");
  assert.equal(await unlock(popup, P), "unlocked", "the extension did not unlock with the new passphrase");
  await worker.evaluate(() => addOtpUri("otpauth://totp/AfterPass:s?secret=GEZDGNBVGY3TQOJQ&issuer=AfterPass"));
  await popup.waitForFunction(() => [...document.querySelectorAll("#entries .issuer")].some(n => n.textContent === "AfterPass"), null, { timeout: 10000 });
  log("web passphrase change: the extension stayed locked (no sign-in), refused the old passphrase, accepted the new one and added an account");

  // 2. The extension changes the passphrase.
  const old2 = P; P = "stale-passphrase-three";
  await freshExtension(); await popup.click("#settings"); await popup.waitForTimeout(400); await popup.click("#settings-lock");
  await popup.fill("#lock-passcode", P); await popup.fill("#lock-confirm", P); await popup.click('#lock-form button[type="submit"]');
  await popup.waitForFunction(() => /Lock protection saved/.test(document.getElementById("settings-message").textContent), null, { timeout: 30000 });
  await popup.waitForTimeout(400); if (await popup.evaluate(() => !document.getElementById("settings-back").classList.contains("hidden"))) await popup.click("#settings-back");
  await ageClients();
  await expectLockedOnly("web app", web);
  assert.match(await unlock(web, old2), /Incorrect passphrase/, "the web app accepted the old passphrase");
  assert.equal(await unlock(web, P), "unlocked", "the web app did not unlock with the new passphrase");
  log("extension passphrase change: the web app stayed locked (no sign-in), refused the old passphrase, accepted the new one");

  // 3. Rotation in the web app, then in the extension.
  await freshWeb(); await web.click("#open-settings"); await web.click("#settings-key-rotate");
  await web.waitForSelector("#confirm-dialog[open]"); await web.fill("#confirm-passkey", P); await web.click("#confirm-accept");
  await web.waitForFunction(() => /rotated to version/.test(document.getElementById("toast").textContent), null, { timeout: 30000 });
  await ageClients();
  await expectLockedOnly("extension", popup);
  assert.equal(await unlock(popup, P), "unlocked");
  await freshExtension(); await popup.click("#settings"); await popup.waitForTimeout(400); await popup.click("#settings-key-rotate");
  await popup.waitForSelector("#confirm-dialog[open]"); await popup.fill("#confirm-passkey", P); await popup.click("#confirm-accept");
  await popup.waitForFunction(() => /rotated to version/.test(document.getElementById("settings-message").textContent), null, { timeout: 30000 });
  await popup.click("#settings-back"); await popup.waitForTimeout(400);
  await ageClients();
  await expectLockedOnly("web app", web);
  assert.equal(await unlock(web, P), "unlocked");
  log("rotations in both directions: the other client stayed locked (no sign-in) and unlocked with the passphrase");

  // 4. The change is made while the other client is closed (popup) or reloading (web tab), and that client's first
  //    requests after opening fail for a moment (a busy server, a dropped connection): it must not mistake that
  //    for a sign-out. It opens locked (or opens its codes and then locks once a request gets through: three failed
  //    requests in a row mean up to two 5-10 s retry delays), never "sign in with Google".
  await popup.close();
  const old4 = P; P = "stale-passphrase-four";
  await freshWeb(); await web.click("#open-settings"); await web.click("#settings-lock");
  await web.fill("#lock-passcode", P); await web.fill("#lock-confirm", P); await web.click('#lock-form button[type="submit"]');
  await web.waitForFunction(() => !document.getElementById("lock-dialog").open, null, { timeout: 30000 });
  await ageClients();
  await control("failNext=3&failClient=extension");
  const popup2 = await context.newPage(); popup2.on("pageerror", e => errors.push(`popup: ${e.message}`));
  await popup2.goto(`chrome-extension://${extensionId}/popup.html`);
  let screens = await watchScreens(popup2, 30000);
  log("extension opened during temporary server failures after a web passphrase change:", screens.join(" -> "));
  assert(!screens.some(x => x.startsWith("signed-out")), `the extension went to "sign in with Google" during temporary failures: ${screens.join(" -> ")}`);
  assert.equal(screens[screens.length - 1].split("@")[0], "unlock", `the extension did not end on the lock screen: ${screens.join(" -> ")}`);
  assert.match(await unlock(popup2, old4), /Incorrect passphrase/, "the extension accepted the old passphrase");
  assert.equal(await unlock(popup2, P), "unlocked", "the extension did not unlock with the new passphrase");
  // The other way round: the extension changes the passphrase, the web tab reloads while the server falters.
  const old5 = P; P = "stale-passphrase-five";
  await freshExtension(); await popup2.click("#settings"); await popup2.waitForTimeout(400); await popup2.click("#settings-lock");
  await popup2.fill("#lock-passcode", P); await popup2.fill("#lock-confirm", P); await popup2.click('#lock-form button[type="submit"]');
  await popup2.waitForFunction(() => /Lock protection saved/.test(document.getElementById("settings-message").textContent), null, { timeout: 30000 });
  await control("failNext=3&failClient=web");
  await web.reload();
  screens = await watchScreens(web, 30000);
  log("web app reloaded during temporary server failures after an extension passphrase change:", screens.join(" -> "));
  assert(!screens.some(x => x.startsWith("signed-out")), `the web app went to "sign in with Google" during temporary failures: ${screens.join(" -> ")}`);
  assert.equal(screens[screens.length - 1].split("@")[0], "unlock", `the web app did not end on the lock screen: ${screens.join(" -> ")}`);
  assert.match(await unlock(web, old5), /Incorrect passphrase/, "the web app accepted the old passphrase");
  assert.equal(await unlock(web, P), "unlocked", "the web app did not unlock with the new passphrase");
  log("temporary failures while opening after a passphrase change: both clients stayed signed in, locked, and accepted only the new passphrase");
  assert.deepEqual(errors, []);
 } finally { await context.close(); await webBrowser.close(); }
})().catch(error => { console.error(`[${label}] FAILED`, error); process.exitCode = 1; });
