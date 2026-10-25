// Like web-vault-replaced, for the extension: the server's vault is replaced by another device (here the web
// app) after its data was deleted, while the extension still holds the older vault with a higher revision.
// (1) The extension still has an account the server lacks: unlocking reports it and keeps the older vault
//     until the user chooses the server's vault, which then works and rotates.
// (2) Nothing would be lost: the extension's rotation takes the server's vault by itself and succeeds.
const API = `http://localhost:${process.env.API_PORT || 8080}`;
const { chromium } = require("playwright");
const path = require("path"), os = require("os"), fs = require("fs");
const [label, extDir] = [process.argv[2], process.argv[3]];
const base = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = () => { const iat = Math.floor(Date.now() / 1000); return `${b64({ alg: "RS256" })}.${b64({ sub: "user-1", name: "T", email: "t@example.com", iat, exp: iat + 3600 })}.sig`; };
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };
const P = "first-passphrase-1";

async function extension() {
  const context = await chromium.launchPersistentContext(fs.mkdtempSync(path.join(os.tmpdir(), `lockstep-profile-${label}-`)), { channel: "chromium", headless: true,
    ignoreDefaultArgs: ["--disable-extensions"], args: ["--headless=new", `--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`] });
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  for (let i = 0; i < 100; i++) { if (await worker.evaluate(() => Boolean(globalThis.chrome?.storage) && typeof setTimeout === "function").catch(() => false)) break; await new Promise(r => setTimeout(r, 100)); }
  return { context, worker };
}
const fresh = (worker) => worker.evaluate(async (token) => { await chrome.storage.session.set({ idToken: token, tokenExpiry: Date.now() + 3600e3, interactiveSignInAt: Date.now() }); }, jwt());
async function setUpExtension(worker, uri) {
  await worker.evaluate(async ([token, P, uri]) => {
    await chrome.storage.local.set({ vaultSubject: "user-1", vaultDisplayName: "T", appSessionId: "session-token", appSessionExpiry: Date.now() + 864e5 });
    await chrome.storage.session.set({ idToken: token, tokenExpiry: Date.now() + 3600e3, interactiveSignInAt: Date.now(), newAccountSetupAuthorized: true });
    await setLockConfig(P, 300, false, true);
    if (uri) await importEntries([uri]);
  }, [jwt(), P, uri]);
}
async function rotate(worker) {
  await fresh(worker);
  return worker.evaluate(async (P) => { try { const r = await rotateEncryptionKey(P); return `rotated to version ${r.version}`; } catch (e) { return `${e.code}: ${e.message}`; } }, P);
}
const issuers = (worker) => worker.evaluate(async () => (await listEntries()).map(e => e.issuer));
// The server's data is deleted; the web app (another device) sets up a new vault with one account.
async function replaceFromWeb(browser, issuer) {
  await control("wipeVault=1");
  const context = await browser.newContext({ serviceWorkers: "block" });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType: "application/javascript", body: "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  const page = await context.newPage();
  await page.goto(base); await page.waitForTimeout(800);
  await page.evaluate(t => onGoogleCredential({ credential: t }), jwt());
  await page.waitForSelector("#lock-dialog[open]", { timeout: 15000 });
  await page.fill("#lock-passcode", P); await page.fill("#lock-confirm", P); await page.click("#lock-form button[type=submit]");
  await page.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await page.click("#open-add"); await page.click("#open-manual");
  await page.fill("#manual-issuer", issuer); await page.fill("#manual-account", "a@x.com"); await page.fill("#manual-secret", "JBSWY3DPEHPK3PXP");
  await page.click("#manual-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 1, null, { timeout: 30000 });
  await page.waitForTimeout(1500);
  await context.close();
}

(async () => {
  const browser = await chromium.launch();
  // Case 1
  await control("reset=1"); await fetch(`${API}/api/v1/session`, { method: "POST" });
  let { context, worker } = await extension();
  await setUpExtension(worker, "otpauth://totp/Alpha:a@x.com?secret=JBSWY3DPEHPK3PXP&issuer=Alpha");
  log("rotation before the wipe:", await rotate(worker));
  await replaceFromWeb(browser, "Bravo");
  const unlock = await worker.evaluate(async (P) => { await lockVault(); return verifyLock(P); }, P);
  log("unlock reports:", JSON.stringify(unlock).slice(0, 200));
  check(unlock.unlocked && /1 account/.test(unlock.replaced || ""), "unlocking did not report the replaced vault");
  const kept = await issuers(worker);
  log("kept the older vault:", JSON.stringify(kept));
  check(kept.includes("Alpha"), "the older vault's account is not available any more");
  const refused = await rotate(worker);
  log("rotation before choosing:", refused.slice(0, 120));
  check(/^VAULT_REPLACED/.test(refused), `rotation was not refused with VAULT_REPLACED: ${refused}`);
  const adopted = await worker.evaluate(async (P) => adoptServerVaultNow(P), P);
  const now = await issuers(worker);
  log("after choosing the server's vault:", JSON.stringify(adopted), JSON.stringify(now));
  check(adopted.unlocked && !adopted.replaced && JSON.stringify(now) === JSON.stringify(["Bravo"]), "choosing the server's vault did not switch to it");
  const rotated = await rotate(worker);
  log("rotation afterwards:", rotated);
  check(/rotated to version 2/.test(rotated), `rotation failed after switching: ${rotated}`);
  await context.close();

  // Case 2
  await control("reset=1"); await fetch(`${API}/api/v1/session`, { method: "POST" });
  ({ context, worker } = await extension());
  await setUpExtension(worker, null);
  log("rotation before the wipe:", await rotate(worker));
  await replaceFromWeb(browser, "Charlie");
  const result = await rotate(worker);
  const st = await control("");
  log("rotation with the replaced vault:", result, "| server key version", st.keyVersion);
  check(/rotated to version 2/.test(result) && st.keyVersion === 2, `rotation was refused: ${result}`);
  const shown = await issuers(worker);
  log("shows:", JSON.stringify(shown));
  check(JSON.stringify(shown) === JSON.stringify(["Charlie"]), "the server's accounts are not shown");
  const reopened = await worker.evaluate(async (P) => { await lockVault(); return (await verifyLock(P)).unlocked; }, P);
  check(reopened, "the vault did not unlock after the rotation");
  await context.close(); await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
