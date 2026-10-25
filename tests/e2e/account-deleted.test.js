// The account is deleted on the server (its user record and sessions removed) while a client still holds its old
// vault. The client must show the sign-in screen; after signing in it must offer to create a passphrase and stay
// there (no jump to "unlock" for a vault that no longer exists); saving the passphrase opens the new, empty vault
// unlocked, and accounts can be added. Checked for the extension popup and for the web app.
const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
const OLD = "account-deleted-old", NEW = "account-deleted-new";
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = (nonce) => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Deleted",email:"d@example.test",nonce,iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const log = (...values) => console.log(`[${label}]`, ...values);
const control = q => fetch(`${API}/__control?${q}`).then(r => r.json());
const googleStub = "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};";
// Which screen is showing; "setup" is the create-passphrase dialog.
const screenOf = page => page.evaluate(() => {
 const shown = id => { const n = document.getElementById(id); return Boolean(n && !n.classList.contains("hidden") && n.getClientRects().length); };
 if (document.getElementById("lock-dialog")?.open) return "setup";
 if (shown("unlock-form")) return "unlock";
 if (shown("signed-out")) return "signed-out";
 if (shown("restore")) return "restore";
 if (shown("signed-in")) return "codes";
 return "loading";
});
// Samples the screen every 50 ms for a while and returns the distinct sequence.
async function watchScreens(page, millis) {
 const seen = [];
 for (const end = Date.now() + millis; Date.now() < end;) {
  const s = await screenOf(page).catch(() => "loading");
  if (seen[seen.length - 1] !== s) seen.push(s);
  await page.waitForTimeout(50);
 }
 return seen;
}
(async () => {
 await control("reset=1"); await control("perClientSessions=1");
 const context = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-deleted-${Date.now()}`), {
  channel:"chromium", headless:true, ignoreDefaultArgs:["--disable-extensions"],
  args:["--headless=new", `--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`] });
 try {
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:googleStub }));
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const extensionId = worker.url().split("/")[2];
  const errors = [];
  // Google's sign-in window, as the extension sees it: returns a token for the nonce it asked for.
  const header = b64({alg:"RS256"});
  await worker.evaluate(header => {
   AUTHSYNC_CONFIG.googleClientId = "test-client.apps.googleusercontent.com";
   chrome.identity.launchWebAuthFlow = async ({ url }) => {
    const nonce = new URL(url).searchParams.get("nonce"), now = Math.floor(Date.now()/1000);
    const body = btoa(JSON.stringify({sub:"user-1",name:"Deleted",email:"d@example.test",nonce,iat:now,exp:now+3600})).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
    return `${chrome.identity.getRedirectURL("google")}#id_token=${header}.${body}.sig`;
   };
  }, header);
  // The web app first creates the account; the extension signs in and holds the vault, with one account.
  const web = await context.newPage(); web.on("pageerror", e => errors.push(`web: ${e.message}`));
  await web.goto(WEB); await web.waitForTimeout(500);
  await web.evaluate(t => onGoogleCredential({ credential: t }), token());
  await web.waitForSelector("#lock-dialog[open]");
  await web.fill("#lock-passcode", OLD); await web.fill("#lock-confirm", OLD); await web.click('#lock-form button[type="submit"]');
  await web.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await web.evaluate(() => importUris(["otpauth://totp/Old:d?secret=JBSWY3DPEHPK3PXP&issuer=Old"]));
  const popup = await context.newPage(); popup.on("pageerror", e => errors.push(`popup: ${e.message}`));
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  await popup.waitForSelector("#signed-out:not(.hidden)");
  await popup.click("#login");
  const firstScreens = await watchScreens(popup, 4000);
  if (firstScreens[firstScreens.length - 1] !== "unlock") throw Error(`setup: the extension did not ask to unlock: ${firstScreens.join(" -> ")} | ${await popup.textContent("#status").catch(() => "")}`);
  await popup.fill("#unlock-passcode", OLD); await popup.click('#unlock-form button[type="submit"]');
  await popup.waitForFunction(() => [...document.querySelectorAll("#entries .issuer")].some(n => n.textContent === "Old"), null, { timeout: 15000 });
  await popup.close(); await web.close();
  log("before: the extension and the web app hold the account's vault");

  // The account is deleted on the server: user record, vault, sessions.
  await control("reset=1"); await control("perClientSessions=1");

  // Extension: sign-in screen, then create passphrase (and it stays there), then the new empty vault.
  const p2 = await context.newPage(); p2.on("pageerror", e => errors.push(`popup: ${e.message}`));
  await p2.goto(`chrome-extension://${extensionId}/popup.html`);
  await p2.waitForSelector("#signed-out:not(.hidden)", { timeout: 10000 });
  await p2.click("#login");
  const afterSignIn = await watchScreens(p2, 35000);
  log("extension screens after signing in:", afterSignIn.join(" -> "));
  assert.equal(afterSignIn[afterSignIn.length - 1], "setup", `the extension did not stay on "create passphrase": ${afterSignIn.join(" -> ")}`);
  assert(!afterSignIn.includes("unlock"), `the extension asked to unlock a vault that no longer exists: ${afterSignIn.join(" -> ")}`);
  await p2.fill("#lock-passcode", NEW); await p2.fill("#lock-confirm", NEW); await p2.click('#lock-form button[type="submit"]');
  const afterSetup = await watchScreens(p2, 5000);
  log("extension screens after creating the passphrase:", afterSetup.join(" -> "));
  assert.equal(afterSetup[afterSetup.length - 1], "codes", `the extension did not open the new vault: ${afterSetup.join(" -> ")}`);
  assert(!afterSetup.includes("unlock"), `the extension asked to unlock right after creating the passphrase: ${afterSetup.join(" -> ")}`);
  assert.equal(await p2.evaluate(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length), 0, "the old vault's accounts are still shown");
  await worker.evaluate(() => addOtpUri("otpauth://totp/New:d?secret=GEZDGNBVGY3TQOJQ&issuer=New"));
  await p2.waitForFunction(() => [...document.querySelectorAll("#entries .issuer")].some(n => n.textContent === "New"), null, { timeout: 10000 });
  for (const s = Date.now(); (await control("")).entries.length !== 1;) { if (Date.now() - s > 10000) throw Error("the new account was not uploaded"); await p2.waitForTimeout(100); }
  log("extension: new passphrase created, empty vault opened unlocked, a new account added and uploaded");

  // Web app (which still holds the old vault): sign-in screen, then it unlocks with the passphrase just created.
  const w2 = await context.newPage(); w2.on("pageerror", e => errors.push(`web: ${e.message}`));
  await w2.goto(WEB);
  const webScreens = await watchScreens(w2, 4000);
  log("web app screens on opening:", webScreens.join(" -> "));
  assert.equal(webScreens[webScreens.length - 1], "signed-out", `the web app did not ask to sign in: ${webScreens.join(" -> ")}`);
  await w2.evaluate(t => onGoogleCredential({ credential: t }), token());
  await w2.waitForSelector("#unlock-form", { state: "visible", timeout: 10000 });
  await w2.fill("#unlock-passcode", OLD); await w2.click('#unlock-form button[type="submit"]');
  await w2.waitForFunction(() => document.getElementById("unlock-error").textContent.trim() || !document.getElementById("signed-in").classList.contains("hidden"), null, { timeout: 15000 });
  const oldResult = { error: (await w2.textContent("#unlock-error")).trim(), screen: await screenOf(w2), toast: await w2.textContent("#toast"),
   names: await w2.evaluate(() => [...document.querySelectorAll("#entries .issuer")].map(n => n.textContent)) };
  log("web app, deleted vault's passphrase:", JSON.stringify(oldResult));
  assert.match(oldResult.error, /Incorrect passphrase/, "the web app accepted the deleted vault's passphrase");
  await w2.evaluate(() => { document.getElementById("unlock-error").textContent = ""; });
  await w2.fill("#unlock-passcode", NEW); await w2.click('#unlock-form button[type="submit"]');
  const opened = await w2.waitForFunction(() => [...document.querySelectorAll("#entries .issuer")].map(n => n.textContent).join() === "New", null, { timeout: 15000 }).then(() => true, () => false);
  if (!opened) throw Error(`the web app did not show exactly the new vault's accounts after the new passphrase: ${JSON.stringify({ error: (await w2.textContent("#unlock-error")).trim(), screen: await screenOf(w2), toast: await w2.textContent("#toast"),
   names: await w2.evaluate(() => [...document.querySelectorAll("#entries .issuer")].map(n => n.textContent)), restore: await w2.evaluate(() => document.getElementById("restore")?.innerText?.slice(0, 300)), server: (await control("")).entries.length })}`);
  log("web app: refused the deleted vault's passphrase, opened the new vault with the new one (the deleted vault's account is gone)");

  // The account is deleted again; this time the web app signs in first and must stay on "create passphrase".
  await control("reset=1"); await control("perClientSessions=1");
  await w2.reload();
  const reopened = await watchScreens(w2, 4000);
  assert.equal(reopened[reopened.length - 1], "signed-out", `the web app did not ask to sign in: ${reopened.join(" -> ")}`);
  await w2.evaluate(t => onGoogleCredential({ credential: t }), token());
  const webSetup = await watchScreens(w2, 35000);
  log("web app screens after signing in:", webSetup.join(" -> "));
  assert.equal(webSetup[webSetup.length - 1], "setup", `the web app did not stay on "create passphrase": ${webSetup.join(" -> ")}`);
  assert(!webSetup.includes("unlock"), `the web app asked to unlock a vault that no longer exists: ${webSetup.join(" -> ")}`);
  const NEWER = "account-deleted-newer";
  await w2.fill("#lock-passcode", NEWER); await w2.fill("#lock-confirm", NEWER); await w2.click('#lock-form button[type="submit"]');
  const webAfterSetup = await watchScreens(w2, 5000);
  log("web app screens after creating the passphrase:", webAfterSetup.join(" -> "));
  assert.equal(webAfterSetup[webAfterSetup.length - 1], "codes", `the web app did not open the new vault: ${webAfterSetup.join(" -> ")}`);
  assert.equal(await w2.evaluate(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length), 0, "the web app still shows a deleted account");
  await w2.evaluate(() => importUris(["otpauth://totp/Newer:d?secret=MFRGGZDFMZTWQ2LK&issuer=Newer"]));
  await w2.waitForFunction(() => [...document.querySelectorAll("#entries .issuer")].some(n => n.textContent === "Newer"), null, { timeout: 10000 });
  log("web app: new passphrase created, empty vault opened unlocked, a new account added");
  // The extension (signed out by the deletion) signs in and unlocks the web app's new vault.
  await p2.reload();
  await p2.waitForSelector("#signed-out:not(.hidden)", { timeout: 10000 });
  await p2.click("#login");
  await p2.waitForSelector("#unlock-form", { state: "visible", timeout: 10000 });
  await p2.fill("#unlock-passcode", NEWER); await p2.click('#unlock-form button[type="submit"]');
  await p2.waitForFunction(() => [...document.querySelectorAll("#entries .issuer")].map(n => n.textContent).join() === "Newer", null, { timeout: 15000 });
  log("extension: signed in again and unlocked the web app's new vault");
  assert.deepEqual(errors, []);
 } finally { await context.close(); }
})().catch(error => { console.error(`[${label}] FAILED`, error); process.exitCode = 1; });
