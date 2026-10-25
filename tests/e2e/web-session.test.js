const API = `http://localhost:${process.env.API_PORT || 8080}`;
const { chromium } = require("playwright");
const [label, port] = [process.argv[2], process.argv[3]];
const base = `http://localhost:${port}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJwt = `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Test User",email:"t@example.com",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };

(async () => {
  await control("reset=1");
  const browser = await chromium.launch();
  const context = await browser.newContext({ acceptDownloads: true, serviceWorkers: "block" });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType: "application/javascript", body: "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  await context.route("https://accounts.google.com/gsi/style", r => r.fulfill({ contentType: "text/css", body: "/* Google stylesheet fixture */" }));
  const page = await context.newPage();
  const errors = []; page.on("pageerror", e => errors.push(e.message));
  await page.goto(base); await page.waitForTimeout(1000);
  await page.evaluate(t => onGoogleCredential({ credential: t }), fakeJwt);
  await page.waitForSelector("#lock-dialog[open]");
  await page.fill("#lock-passcode", "1234pass-long"); await page.fill("#lock-confirm", "1234pass-long");
  await page.click("#lock-form button[type=submit]");
  await page.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await page.click("#open-add"); await page.click("#open-manual");
  await page.fill("#manual-issuer", "Manual"); await page.fill("#manual-account", "me@example.com"); await page.fill("#manual-secret", "JBSWY3DPEHPK3PXP");
  await page.click("#manual-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 1);
  log("manual add ok, server:", (await control("")).entries);
  // Lock, reload, unlock.
  await page.click("#lock-now"); await page.waitForSelector("#locked:not(.hidden)");
  await page.reload();
  await page.waitForSelector("#locked:not(.hidden)", { timeout: 15000 });
  log("after reload while locked: lock screen shown");
  await control("clearCalls=1");
  await page.fill("#unlock-passcode", "1234pass-long"); await page.click("#unlock-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 1, null, { timeout: 15000 });
  log("unlocked, calls:", JSON.stringify((await control("")).calls));
  // Wrong passkey path.
  await page.click("#lock-now"); await page.fill("#unlock-passcode", "wrong-pass"); await page.click("#unlock-form button[type=submit]");
  await page.waitForTimeout(2500);
  log("wrong passkey message:", (await page.textContent("#unlock-error")).trim());
  await page.fill("#unlock-passcode", "1234pass-long"); await page.click("#unlock-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 1, null, { timeout: 15000 });
  // Another device logs in: this session must be signed out with the notice.
  if (process.env.LOCKED) { await page.click("#lock-now"); await page.waitForSelector("#locked:not(.hidden)"); log("vault locked before the other login"); }
  await fetch(`${API}/api/v1/session`, { method: "POST" }).then(r => r.json());
  await fetch(`${API}/__control?x=1`);
  // mock: replace session token
  await page.evaluate(() => null);
  const t0 = Date.now();
  await fetch(`${API}/__control?revoke=1`);
  log("revoked; user returns to the tab (focus)...");
  await page.waitForTimeout(6000);
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  try { await page.waitForSelector("#signed-out:not(.hidden)", { timeout: 40000 }); }
  catch (e) { log("not signed out; calls since revoke:", JSON.stringify((await control("")).calls.slice(-8)), "visible views:", await page.evaluate(() => ["signed-in","signed-out","locked"].filter(id => !document.getElementById(id).classList.contains("hidden")))); throw e; }
  log(`signed out after ${Date.now() - t0} ms, toast:`, (await page.textContent("#toast")).trim());
  check(errors.length === 0, `page errors: ${errors}`);
  log("errors:", errors.length ? errors : "none");
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
