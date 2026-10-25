// Rotation on a device that has not seen the latest key change: another device re-protected the key (for
// example with Argon2id), so the server's vault revision moved on. The rotation must take the server's key
// (the same passphrase opens it) and succeed, instead of being refused as "changed on another device".
const API = `http://localhost:${process.env.API_PORT || 8080}`;
const { chromium } = require("playwright");
const [label, port] = [process.argv[2], process.argv[3]];
const base = `http://localhost:${port}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = () => { const iat = Math.floor(Date.now() / 1000); return `${b64({ alg: "RS256" })}.${b64({ sub: "user-1", name: "T", email: "t@example.com", iat, exp: iat + 3600 })}.sig`; };
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };
const P = "first-passphrase-1";
const waitCount = (page, n) => page.waitForFunction(c => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === c, n, { timeout: 30000 });

async function device(browser) {
  const context = await browser.newContext({ acceptDownloads: true, serviceWorkers: "block" });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType: "application/javascript", body: "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  const page = await context.newPage();
  page.errors = []; page.on("pageerror", e => page.errors.push(e.message));
  await page.goto(base); await page.waitForTimeout(800);
  await page.evaluate(t => onGoogleCredential({ credential: t }), jwt());
  return page;
}
async function rotate(page) {
  await page.evaluate(t => { state.token = t; }, jwt()); // a fresh Google sign-in
  await page.click("#open-settings"); await page.click("#settings-key-rotate");
  await page.waitForSelector("#confirm-dialog[open]"); await page.fill("#confirm-passkey", P); await page.click("#confirm-accept");
  await page.waitForFunction(() => /rotated|changed|could not|refused/i.test(document.getElementById("toast").textContent), null, { timeout: 30000 });
  return (await page.textContent("#toast")).trim();
}

(async () => {
  await control("reset=1"); await control("argon2id=0");
  const browser = await chromium.launch();
  // Device A creates a PBKDF2-protected vault; device B opens it.
  const a = await device(browser);
  await a.waitForSelector("#lock-dialog[open]");
  await a.fill("#lock-passcode", P); await a.fill("#lock-confirm", P); await a.click("#lock-form button[type=submit]");
  await a.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await a.click("#open-add"); await a.click("#open-manual");
  await a.fill("#manual-issuer", "Alpha"); await a.fill("#manual-account", "a@x.com"); await a.fill("#manual-secret", "JBSWY3DPEHPK3PXP");
  await a.click("#manual-form button[type=submit]"); await waitCount(a, 1); await a.waitForTimeout(1500);
  const b = await device(browser);
  await b.waitForSelector("#locked:not(.hidden)", { timeout: 15000 });
  await b.fill("#unlock-passcode", P); await b.click("#unlock-form button[type=submit]"); await waitCount(b, 1);
  const before = await b.evaluate(() => LockstepVault.expectedRevision("user-1"));
  // The server switches Argon2id on; device A's next unlock re-protects the key (revision moves on).
  await control("argon2id=1");
  await a.click("#lock-now"); await a.reload();
  await a.waitForSelector("#locked:not(.hidden)", { timeout: 15000 });
  await a.fill("#unlock-passcode", P); await a.click("#unlock-form button[type=submit]"); await waitCount(a, 1);
  await a.waitForTimeout(2000);
  let st = await control("");
  log("device B expects revision", before, "| server now:", st.revision, st.wrapping);
  check(st.revision > before, "the test did not move the server's revision on");
  // Device B, still open, rotates the recovery key.
  const result = await rotate(b);
  st = await control("");
  log("device B rotation:", result, "| server key version:", st.keyVersion, "| revision:", st.revision);
  check(/rotated to version 2/.test(result) && st.keyVersion === 2, `rotation on the device with the older revision failed: ${result}`);
  // A real master-key rotation (not just a rewrap) must be adopted inside the next rotation action.
  const followup = await rotate(a);
  st = await control("");
  log("device A rotates after B without locking or reloading:", followup, "| server key version:", st.keyVersion);
  check(/rotated to version 3/.test(followup) && st.keyVersion === 3, `rotation after another device's master-key change required a manual reload: ${followup}`);
  // The normal refresh (used by focus and the timer) detects metadata changes too.
  await b.evaluate(() => loadEntries(true));
  await b.waitForSelector("#locked:not(.hidden)");
  check(await b.evaluate(() => state.lockConfig.wrappedKey.currentVersion === 3), "normal refresh did not adopt the remotely rotated key");
  log("device B detected the remote rotation and requested unlock without reloading");
  await b.fill("#unlock-passcode", P); await b.click("#unlock-form button[type=submit]"); await waitCount(b, 1);
  log("device B unlocks after the rotation: yes");
  const errors = [...a.errors, ...b.errors];
  check(errors.length === 0, `page errors: ${errors}`);
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
