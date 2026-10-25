const API = `http://localhost:${process.env.API_PORT || 8080}`;
// Passkey stays local, 8-char rule, delta sync, CSP, lazy Google script.
const { chromium } = require("playwright");
const [label, port] = [process.argv[2], process.argv[3]];
const base = `http://localhost:${port}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJwt = `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Test User",email:"t@example.com",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const uris = ["JBSWY3DPEHPK3PXP","GEZDGNBVGY3TQOJQ","MFRGGZDFMZTWQ2LK"].map((s,i)=>`otpauth://totp/Issuer${i}:user${i}@example.com?secret=${s}&issuer=Issuer${i}`).join("\n");
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };

const issuers = (page) => page.$$eval("#entries .entry:not(.entry-skel) .issuer", n => n.map(x => x.textContent));
(async () => {
  await control("reset=1");
  const browser = await chromium.launch();
  const context = await browser.newContext({ acceptDownloads: true, serviceWorkers: "block" });
  let googleScriptLoads = 0;
  await context.route("https://accounts.google.com/**", r => { googleScriptLoads++; r.fulfill({ contentType: "application/javascript", body: "window.__gsi=[];window.google={accounts:{id:{initialize(){},renderButton(t,o){window.__gsi.push(o.type+'/'+o.theme);},disableAutoSelect(){},prompt(){}}}};" }); });
  let failGoogleStyles = true;
  await context.route("https://accounts.google.com/gsi/style", r => failGoogleStyles ? r.abort() : r.fulfill({ contentType: "text/css", body: "/* Google stylesheet fixture */" }));
  await context.addInitScript(() => { window.__cspViolations = []; document.addEventListener("securitypolicyviolation", e => window.__cspViolations.push(`${e.violatedDirective} ${e.blockedURI}`)); });
  const page = await context.newPage();
  const errors = []; page.on("pageerror", e => errors.push(e.message));
  await page.goto(base); await page.waitForTimeout(1200);
  check(await page.getByRole("button", { name: "Retry Google sign-in" }).isVisible(), "stylesheet failure did not offer a retry");
  check(await page.evaluate(() => !window.__gsi?.length), "an unstyled Google button was rendered");
  failGoogleStyles = false;
  await page.getByRole("button", { name: "Retry Google sign-in" }).click();
  await page.waitForFunction(() => window.__gsi?.length > 0);
  log("signed-out page loaded Google script:", googleScriptLoads > 0);
  check(await page.evaluate(() => Boolean(document.querySelector('link[href="https://accounts.google.com/gsi/style"]')?.sheet)),
    "Google's external stylesheet was not loaded before rendering");
  // Google's button is drawn with its own options, and drawn again for the icon-only header and the dark theme.
  const firstDraw = await page.evaluate(() => [...window.__gsi]);
  await page.setViewportSize({ width: 380, height: 800 }); await page.waitForTimeout(200);
  await page.evaluate(() => applyTheme("dark")); await page.waitForTimeout(100);
  await page.setViewportSize({ width: 1280, height: 800 }); await page.waitForTimeout(200);
  await page.evaluate(() => applyTheme("light"));
  const draws = await page.evaluate(() => window.__gsi);
  log("Google button draws:", JSON.stringify(draws));
  check(firstDraw.at(-1) === "standard/outline" && draws.includes("icon/outline") && draws.includes("icon/filled_black") && draws.includes("standard/filled_black") && draws.at(-1) === "standard/outline",
    "the Google button was not redrawn for the narrow header or the theme");
  await page.evaluate(t => onGoogleCredential({ credential: t }), fakeJwt);
  await page.waitForSelector("#lock-dialog[open]");
  // 6 characters must be refused for a new passkey.
  await page.fill("#lock-passcode", "abc1234567"); await page.fill("#lock-confirm", "abc1234567");
  await page.evaluate(() => document.getElementById("lock-form").requestSubmit());
  await page.waitForTimeout(500);
  log("10-char passphrase message:", (await page.textContent("#lock-error")).trim() || "(form validation blocked it)", "| dialog still open:", await page.evaluate(() => document.getElementById("lock-dialog").open));
  await page.fill("#lock-passcode", "abcd1234-long"); await page.fill("#lock-confirm", "abcd1234-long");
  await page.click("#lock-form button[type=submit]");
  await page.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await page.click("#open-add"); await page.click("#open-uris"); await page.fill("#otp-uris", uris);
  await page.click("#uri-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 3, null, { timeout: 20000 });
  // Reload as a returning user: no Google script, bootstrap only.
  googleScriptLoads = 0; await control("clearCalls=1");
  await page.reload();
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 3, null, { timeout: 20000 });
  await page.waitForTimeout(1500);
  log("signed-in reload loaded Google script:", googleScriptLoads > 0, "| calls:", JSON.stringify((await control("")).calls));
  // Another device renames one account and deletes another; this tab learns it through a delta sync.
  await control("remoteRename=1"); await control("remoteDelete=1"); await control("clearCalls=1");
  await page.waitForTimeout(5200);
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 2, null, { timeout: 15000 });
  await page.waitForTimeout(800);
  check((await issuers(page)).includes("Renamed elsewhere"), "delta sync did not apply the rename");
  log("after delta sync:", JSON.stringify(await issuers(page)), "| calls:", JSON.stringify((await control("")).calls));
  // Lock, then unlock with the new passkey; wrong passkey still rejected.
  await page.click("#lock-now"); await page.fill("#unlock-passcode", "wrong-pass"); await page.click("#unlock-form button[type=submit]");
  await page.waitForTimeout(2500);
  log("wrong passkey:", (await page.textContent("#unlock-error")).trim());
  await page.fill("#unlock-passcode", "abcd1234-long"); await page.click("#unlock-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 2, null, { timeout: 15000 });
  log("unlocked with new passkey: yes");
  // QR code still renders under the security policy.
  await page.click("#entries .entry [data-action=qr]");
  await page.waitForFunction(() => document.getElementById("qr-image").src.startsWith("data:image"), null, { timeout: 10000 });
  await page.click("#close-qr");
  const state = await control("");
  check(state.passcodeSeen === 0, "a request contained the passphrase");
  log("requests that contained a passkey:", state.passcodeSeen);
  const violations = await page.evaluate(() => window.__cspViolations);
  check(violations.length === 0, `CSP violations: ${violations}`);
  check(errors.length === 0, `page errors: ${errors}`);
  log("CSP violations:", JSON.stringify(violations));
  log("errors:", errors.length ? errors : "none");
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
