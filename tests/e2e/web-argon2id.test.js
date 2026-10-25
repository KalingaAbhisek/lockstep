// Argon2id re-protection after unlock, the Google confirmation for key-changing actions, vault reset and
// opening the saved vault before the server answers. Two browser contexts = two devices.
const API = `http://localhost:${process.env.API_PORT || 8080}`;
const { chromium } = require("playwright");
const [label, port] = [process.argv[2], process.argv[3]];
const base = `http://localhost:${port}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const googleToken = (secondsAgo = 0, sub = "user-1") => {
  const iat = Math.floor(Date.now() / 1000) - secondsAgo;
  return `${b64({ alg: "RS256" })}.${b64({ sub, name: "Test User", email: "t@example.com", iat, exp: iat + 3600 })}.sig`;
};
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };
const P1 = "first-passphrase-1", P2 = "second-passphrase-2";
const ARGON2ID = "ARGON2ID-V13/AES-256-GCM";
const waitCount = (page, n) => page.waitForFunction(c => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === c, n, { timeout: 20000 });

async function device(browser, token) {
  const context = await browser.newContext({ serviceWorkers: "block", acceptDownloads: true });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType: "application/javascript", body: "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  await context.route("https://accounts.google.com/gsi/style", r => r.fulfill({ contentType: "text/css", body: "/* Google stylesheet fixture */" }));
  await context.addInitScript(() => { window.__csp = []; document.addEventListener("securitypolicyviolation", e => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`)); });
  const page = await context.newPage();
  page.errors = []; page.on("pageerror", e => page.errors.push(e.message));
  await page.goto(base); await page.waitForTimeout(800);
  await page.evaluate(t => onGoogleCredential({ credential: t }), token);
  return page;
}
async function unlock(page, passphrase) {
  await page.waitForSelector("#locked:not(.hidden)", { timeout: 15000 });
  await page.fill("#unlock-passcode", passphrase); await page.click("#unlock-form button[type=submit]");
}

(async () => {
  await control("reset=1"); await control("argon2id=0");
  const browser = await chromium.launch();

  // Device A sets up a PBKDF2-protected vault (Argon2id still off on the server).
  const a = await device(browser, googleToken());
  await a.waitForSelector("#lock-dialog[open]");
  await a.fill("#lock-passcode", P1); await a.fill("#lock-confirm", P1);
  await a.click("#lock-form button[type=submit]");
  await a.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await a.click("#open-add"); await a.click("#open-manual");
  await a.fill("#manual-issuer", "Alpha"); await a.fill("#manual-account", "a@example.com"); await a.fill("#manual-secret", "JBSWY3DPEHPK3PXP");
  await a.click("#manual-form button[type=submit]");
  await waitCount(a, 1);
  let st = await control("");
  log("vault key protection with Argon2id off:", st.wrapping);
  check(st.wrapping === "PBKDF2-SHA256/AES-256-GCM", "the vault started with Argon2id while it was switched off");

  // Argon2id switched on: the next unlock re-protects the vault and saves it on the server.
  await control("argon2id=1");
  await a.click("#lock-now"); await a.reload();
  await unlock(a, P1); await waitCount(a, 1);
  await a.waitForTimeout(1500);
  st = await control("");
  log("after unlock with Argon2id on:", st.wrapping, "| revision", st.revision);
  check(st.wrapping === ARGON2ID, "unlocking did not re-protect the vault with Argon2id");

  // Opening the saved vault does not wait for the server: codes appear while the startup request is slow.
  await control("latency=2500");
  const started = Date.now();
  await a.reload();
  await waitCount(a, 1);
  const shownAfter = Date.now() - started;
  log(`codes shown after reload with a 2.5 s server delay: ${shownAfter} ms`);
  check(shownAfter < 2000, `codes waited for the server (${shownAfter} ms)`);
  await a.waitForTimeout(3500); // let the startup request finish
  await control("latency=200");

  // Device B (another browser) opens the Argon2id vault with the same passphrase.
  const b = await device(browser, googleToken());
  await unlock(b, P1); await waitCount(b, 1);
  log("second device opened the Argon2id vault");

  // An old Google sign-in: changing the passphrase asks to confirm with Google first.
  await a.evaluate((token) => { state.token = token; }, googleToken(600));
  await a.click("#open-settings"); await a.click("#settings-lock");
  await a.waitForSelector("#lock-dialog[open]");
  await a.fill("#lock-passcode", P2); await a.fill("#lock-confirm", P2);
  await a.click("#lock-form button[type=submit]");
  await a.waitForSelector("#reauth-dialog[open]", { timeout: 10000 });
  log("Google confirmation asked:", (await a.textContent("#reauth-message")).trim());
  await a.evaluate((token) => onGoogleCredential({ credential: token }), googleToken(0, "someone-else"));
  const wrongAccount = (await a.textContent("#reauth-error")).trim();
  log("other Google account refused:", wrongAccount);
  check(/same|belongs/.test(wrongAccount) && await a.isVisible("#reauth-dialog"), "a different Google account was accepted");
  await a.evaluate((token) => onGoogleCredential({ credential: token }), googleToken());
  await a.waitForFunction(() => !document.getElementById("lock-dialog").open, null, { timeout: 20000 });
  st = await control("");
  log("passphrase changed after confirming:", st.wrapping, "| revision", st.revision);
  check(st.wrapping === ARGON2ID, "the changed passphrase was not protected with Argon2id");

  // The server itself refuses a key change without a recent Google sign-in.
  const refused = await a.evaluate(async (token) => {
    state.token = token;
    const wrappedKey = await LockstepVault.exportWrappedKey("user-1");
    const expectedRevision = await LockstepVault.expectedRevision("user-1");
    try { await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ timeoutSeconds: 300, lockOnScreenLock: false, expectedRevision, wrappedKey: { ...wrappedKey, wrappedMasterKey: wrappedKey.wrappedMasterKey.replace(/^./, c => c === "A" ? "B" : "A") } }) }); return "accepted"; }
    catch (error) { return error.code; }
  }, googleToken(600));
  log("server refuses a key change with an old sign-in:", refused);
  check(refused === "REAUTH_REQUIRED", "the server accepted a key change without a recent Google sign-in");

  // Reset (offered on the restore page) with an old sign-in: confirm with Google, then everything is
  // deleted and the browser signs out.
  await a.evaluate((token) => { state.token = token; showRestore(); }, googleToken(600));
  await a.evaluate(() => { resetVault(); }); // the restore page's Reset button
  await a.waitForSelector("#confirm-dialog[open]"); await a.fill("#confirm-passkey", P2); await a.click("#confirm-accept");
  await a.waitForSelector("#reauth-dialog[open]", { timeout: 10000 });
  await a.evaluate((token) => onGoogleCredential({ credential: token }), googleToken());
  await a.waitForSelector("#signed-out:not(.hidden)", { timeout: 15000 });
  st = await control("");
  log("vault reset after confirming:", st.resets === 1, "| accounts left:", st.entries.length);
  check(st.resets === 1 && st.entries.length === 0, "the confirmed reset did not delete the vault");

  const csp = [...await a.evaluate(() => window.__csp), ...await b.evaluate(() => window.__csp)];
  check(csp.length === 0, `Content-Security-Policy / Trusted Types violations: ${csp}`);
  const errors = [...a.errors, ...b.errors];
  check(errors.length === 0, `page errors: ${errors}`);
  log("CSP / Trusted Types violations:", csp.length ? csp : "none", "| errors:", errors.length ? errors : "none");
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
