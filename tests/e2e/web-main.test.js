const API = `http://localhost:${process.env.API_PORT || 8080}`;
// Usage: node test.js <label> <staticPort> [nobootstrap]
const { chromium } = require("playwright");
const [label, port, mode] = [process.argv[2], process.argv[3], process.argv[4]];
const base = `http://localhost:${port}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJwt = `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Test User",email:"t@example.com",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const secrets = ["JBSWY3DPEHPK3PXP","GEZDGNBVGY3TQOJQ","MFRGGZDFMZTWQ2LK","ONSWG4TFOQYTEMZU","KRSXG5BAMFZGK3TP"];
const uris = secrets.map((s,i)=>`otpauth://totp/Issuer${i}:user${i}@example.com?secret=${s}&issuer=Issuer${i}&period=15`).join("\n");
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };

(async () => {
  await control("reset=1"); if (mode === "nobootstrap") await control("nobootstrap=1");
  const browser = await chromium.launch();
  const context = await browser.newContext({ acceptDownloads: true, serviceWorkers: process.env.SW === "allow" ? "allow" : "block" });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType: "application/javascript",
    body: "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  await context.route("https://accounts.google.com/gsi/style", r => r.fulfill({ contentType: "text/css", body: "/* Google stylesheet fixture */" }));
  const page = await context.newPage();
  const errors = []; page.on("pageerror", e => errors.push(e.message)); page.on("console", m => { if (m.type() === "error") errors.push(m.text()); });
  await page.goto(base); await page.waitForTimeout(1500);
  // Sign in (same callback Google invokes) and create lock protection.
  await page.evaluate(t => onGoogleCredential({ credential: t }), fakeJwt);
  await page.waitForSelector("#lock-dialog[open]", { timeout: 15000 });
  await page.fill("#lock-passcode", "1234pass-long"); await page.fill("#lock-confirm", "1234pass-long");
  await page.click("#lock-form button[type=submit]");
  await page.waitForFunction(() => !document.getElementById("lock-dialog").open, null, { timeout: 15000 });
  await page.waitForTimeout(1500);
  // Import five accounts.
  await control("clearCalls=1");
  await page.click("#open-add"); await page.click("#open-uris"); await page.fill("#otp-uris", uris);
  await page.click("#uri-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 5, null, { timeout: 30000 });
  await page.waitForTimeout(2500);
  let state = await control("");
  log("import calls:", state.calls.length, JSON.stringify(state.calls));
  log("server entries:", state.entries.length);
  { // Argon2id is on by default; ARGON2ID=0 and old servers (no feature list) keep PBKDF2.
    const expected = process.env.ARGON2ID !== "0" && mode !== "nobootstrap" ? "ARGON2ID-V13/AES-256-GCM" : "PBKDF2-SHA256/AES-256-GCM";
    check(state.wrapping === expected, `vault key protected with ${state.wrapping}, expected ${expected}`);
    log("vault key protection:", state.wrapping);
  }
  // Reload: measure time until codes are visible.
  await control("clearCalls=1");
  const started = Date.now();
  await page.reload();
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 5 && document.getElementById("app-loading").classList.contains("hidden"), null, { timeout: 30000 });
  const visibleAfter = Date.now() - started;
  await page.waitForTimeout(3000);
  state = await control("");
  log(`codes visible after reload: ${visibleAfter} ms`);
  log("reload calls:", state.calls.length, JSON.stringify(state.calls));
  const summary = await page.textContent("#account-summary");
  log("summary:", summary);
  // Code rollover (15 s period): codes must change without breaking.
  await control("clearCalls=1");
  const before = await page.$$eval("#entries .entry .code", n => n.map(x => x.textContent));
  await page.waitForTimeout(16500);
  const after = await page.$$eval("#entries .entry .code", n => n.map(x => x.textContent));
  state = await control("");
  log("codes changed at rollover:", before.some((c, i) => c !== after[i]), "calls during 16.5s:", JSON.stringify(state.calls));
  // Show a QR code (QR library is loaded lazily).
  await page.click("#entries .entry [data-action=qr]");
  await page.waitForFunction(() => { const i = document.getElementById("qr-image"); return i.src.startsWith("data:image") && !i.classList.contains("hidden"); }, null, { timeout: 10000 });
  log("QR code rendered: yes");
  await page.click("#close-qr");
  { // A QR code that finishes late never appears in a closed dialog, nor in place of a newer account's code.
    const late = await page.evaluate(async () => {
      const original = QRCode.toDataURL, wait = (ms) => new Promise(r => setTimeout(r, ms));
      QRCode.toDataURL = async (uri) => { await wait(uri.includes(state.entries[0].issuer) ? 600 : 50); return `data:image/png;base64,${btoa(uri.slice(0, 40))}`; };
      try {
        void showQr(state.entries[0]); await wait(100); el("qr-dialog").close(); await wait(800);
        const afterClose = el("qr-image").getAttribute("src");
        void showQr(state.entries[0]); await wait(100); void showQr(state.entries[1]); await wait(900);
        const shown = atob(el("qr-image").src.split(",")[1] || "");
        el("qr-dialog").close();
        return { afterClose, shownIsSecond: shown === `otpauth://totp/${encodeURIComponent(state.entries[1].issuer + ":" + state.entries[1].accountName)}`.slice(0, 40) };
      } finally { QRCode.toDataURL = original; }
    });
    check(late.afterClose === null, "a QR code finished after the dialog closed and was left in it");
    check(late.shownIsSecond, "a slower QR code for an earlier account replaced the account shown now");
    log("late QR codes dropped:", late.afterClose === null && late.shownIsSecond);
  }
  // Delete one account through the UI.
  await page.click("#edit-accounts");
  await page.locator("#entries .entry [data-action=delete]").first().click();
  await page.waitForSelector("#confirm-dialog[open]");
  await page.fill("#confirm-passkey","1234pass-long"); await page.click("#confirm-accept");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length===4);
  check((await control("")).entries.length===4,"confirmed deletion did not remove the account on the server");
  // "Failed to load resource" lines are the expected 404/405 fallback checks against an older server.
  const realErrors = errors.filter(message => !message.startsWith("Failed to load resource"));
  check(realErrors.length === 0, `page errors: ${realErrors}`);
  log("errors:", errors.length ? errors : "none");
  log("final server entries:", (await control("")).entries.length, "lock enabled:", (await control("")).lock, "names:", JSON.stringify((await control("")).entries.slice(0,2)));
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
