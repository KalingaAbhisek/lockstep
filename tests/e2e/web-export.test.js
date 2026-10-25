// Exports: the vault passphrase is asked again before a backup or recovery-key download, a backup can be
// encrypted with its own password, and an encrypted backup imports again with that password.
const API = `http://localhost:${process.env.API_PORT || 8080}`;
const { chromium } = require("playwright");
const fs = require("fs");
const [label, port] = [process.argv[2], process.argv[3]];
const base = `http://localhost:${port}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const iat = Math.floor(Date.now() / 1000);
const fakeJwt = `${b64({ alg: "RS256" })}.${b64({ sub: "user-1", name: "Test User", email: "t@example.com", iat, exp: iat + 3600 })}.sig`;
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };
const P1 = "first-passphrase-1", BACKUP = "backup-password-123";
const SECRET = "JBSWY3DPEHPK3PXP";
const waitCount = (page, n) => page.waitForFunction(c => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === c, n, { timeout: 20000 });

async function confirmWith(page, passphrase) {
  await page.waitForSelector("#confirm-dialog[open]");
  await page.fill("#confirm-passkey", passphrase);
  await page.click("#confirm-accept");
}
async function download(page, action) {
  const [file] = await Promise.all([page.waitForEvent("download", { timeout: 30000 }), action()]);
  return { name: file.suggestedFilename(), text: fs.readFileSync(await file.path(), "utf8") };
}

(async () => {
  await control("reset=1");
  const browser = await chromium.launch();
  const context = await browser.newContext({ acceptDownloads: true, serviceWorkers: "block" });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType: "application/javascript", body: "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  await context.route("https://accounts.google.com/gsi/style", r => r.fulfill({ contentType: "text/css", body: "/* Google stylesheet fixture */" }));
  await context.addInitScript(() => { window.__csp = []; document.addEventListener("securitypolicyviolation", e => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`)); });
  const page = await context.newPage();
  const errors = []; page.on("pageerror", e => errors.push(e.message));
  await page.goto(base); await page.waitForTimeout(800);
  await page.evaluate(t => onGoogleCredential({ credential: t }), fakeJwt);
  await page.waitForSelector("#lock-dialog[open]");
  await page.fill("#lock-passcode", P1); await page.fill("#lock-confirm", P1);
  await page.click("#lock-form button[type=submit]");
  await page.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await page.click("#open-add"); await page.click("#open-manual");
  await page.fill("#manual-issuer", "Alpha"); await page.fill("#manual-account", "a@example.com"); await page.fill("#manual-secret", SECRET);
  await page.click("#manual-form button[type=submit]");
  await waitCount(page, 1);

  // A wrong passphrase stops the export before anything is written.
  let downloaded = false; page.once("download", () => { downloaded = true; });
  await page.evaluate(() => el("export-backup").click());
  await confirmWith(page, "not-the-passphrase");
  await page.waitForFunction(() => /Incorrect passphrase/.test(document.getElementById("toast").textContent), null, { timeout: 15000 });
  check(!downloaded && !(await page.isVisible("#backup-dialog")), "an export went ahead with a wrong passphrase");
  log("wrong passphrase refused:", !downloaded);

  // Encrypted backup: password mismatch is caught, then the file holds no readable secret.
  await page.evaluate(() => el("export-backup").click());
  await confirmWith(page, P1);
  await page.waitForSelector("#backup-dialog[open]");
  const warning = await page.textContent("#backup-message");
  check(/synced to cloud storage/.test(warning), "the export does not warn about synced Downloads folders");
  await page.fill("#backup-password", BACKUP); await page.fill("#backup-password-confirm", BACKUP + "x");
  await page.click("#backup-accept");
  await page.waitForFunction(() => /do not match/.test(document.getElementById("backup-error").textContent));
  await page.fill("#backup-password-confirm", BACKUP);
  const encrypted = await download(page, () => page.click("#backup-accept"));
  const parsed = JSON.parse(encrypted.text);
  log("encrypted backup:", encrypted.name, "|", parsed.format, parsed.wrapping, "| secret readable:", encrypted.text.includes(SECRET));
  check(parsed.format === "lockstep-encrypted-backup" && !encrypted.text.includes(SECRET) && !encrypted.text.includes("otpauth"), "the encrypted backup exposes its contents");
  check(encrypted.name.endsWith(".json"), "the encrypted backup has the wrong file name");

  // Without a password: the plain text file as before.
  await page.evaluate(() => el("export-backup").click());
  await confirmWith(page, P1);
  await page.waitForSelector("#backup-dialog[open]");
  const plain = await download(page, () => page.click("#backup-plain"));
  log("plain backup:", plain.name, "| has otpauth:", plain.text.includes("otpauth://totp/"));
  check(plain.text.includes(`secret=${SECRET}`) && plain.name.endsWith(".txt"), "the plain backup is missing its accounts");

  // The recovery key also needs the passphrase.
  await page.click("#open-settings");
  await page.click("#settings-recovery-export");
  const recovery = await download(page, () => confirmWith(page, P1));
  log("recovery key download after passphrase:", /LS2-M-/.test(recovery.text));
  check(/LS2-M-/.test(recovery.text), "the recovery key was not downloaded after the passphrase");
  await page.keyboard.press("Escape");

  // Import the encrypted backup: a wrong password keeps the dialog open, the right one imports.
  // A unique temporary folder (works on Windows, macOS and Linux).
  const backupFile = require("path").join(fs.mkdtempSync(require("path").join(require("os").tmpdir(), "lockstep-backup-")), "backup.json");
  fs.writeFileSync(backupFile, encrypted.text);
  await page.setInputFiles("#backup-file", backupFile);
  await page.waitForSelector("#backup-dialog[open]");
  check(!(await page.isVisible("#backup-password-confirm")) && !(await page.isVisible("#backup-plain")), "the import dialog shows export options");
  await page.fill("#backup-password", "wrong-password-000"); await page.click("#backup-accept");
  await page.waitForFunction(() => /Wrong backup password/.test(document.getElementById("backup-error").textContent), null, { timeout: 30000 });
  await page.fill("#backup-password", BACKUP); await page.click("#backup-accept");
  await waitCount(page, 2);
  log("encrypted backup imported with its password: accounts now", await page.$$eval("#entries .entry:not(.entry-skel)", n => n.length));

  const csp = await page.evaluate(() => window.__csp);
  check(csp.length === 0, `Content-Security-Policy / Trusted Types violations: ${csp}`);
  check(errors.length === 0, `page errors: ${errors}`);
  log("CSP / Trusted Types violations:", csp.length ? csp : "none", "| errors:", errors.length ? errors : "none");
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
