// Data-integrity and UI regressions: edit conflicts, deleted accounts, a refused change that must not block the
// queue, a damaged account, names with non-ASCII letters, the system theme, focus across a code change and
// error messages that go away. Usage: node web-integrity.test.js <label> <staticPort>
const API = `http://localhost:${process.env.API_PORT || 8080}`;
const { chromium } = require("playwright");
const [label, port] = [process.argv[2], process.argv[3]];
const base = `http://localhost:${port}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const NAME = "José Ñúñez प्रिया";
const fakeJwt = `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:NAME,email:"t@example.com",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const secrets = ["JBSWY3DPEHPK3PXP","GEZDGNBVGY3TQOJQ","MFRGGZDFMZTWQ2LK"];
const uris = secrets.map((s,i)=>`otpauth://totp/Issuer${i}:user${i}@example.com?secret=${s}&issuer=Issuer${i}&period=15`).join("\n");
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };
const count = (page) => page.$$eval("#entries .entry:not(.entry-skel)", n => n.length);

(async () => {
  await control("reset=1");
  const browser = await chromium.launch();
  const context = await browser.newContext({ colorScheme: "dark", serviceWorkers: "block" });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType: "application/javascript",
    body: "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  await context.route("https://accounts.google.com/gsi/style", r => r.fulfill({ contentType: "text/css", body: "" }));
  await context.addInitScript(() => { window.__csp = []; document.addEventListener("securitypolicyviolation", e => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`)); });
  const page = await context.newPage();
  const errors = []; page.on("pageerror", e => errors.push(e.message));
  await page.goto(base); await page.waitForTimeout(1200);

  // System theme: a dark device gets the dark theme, with no explicit choice stored.
  const theme = await page.evaluate(() => ({ attr: document.documentElement.dataset.theme || null, bg: getComputedStyle(document.body).backgroundColor }));
  log("theme on a dark device:", JSON.stringify(theme));
  check(theme.attr === null && theme.bg !== "rgb(247, 248, 251)", "the web app did not follow the device's dark theme");

  await page.evaluate(t => onGoogleCredential({ credential: t }), fakeJwt);
  await page.waitForSelector("#lock-dialog[open]", { timeout: 15000 });
  await page.fill("#lock-passcode", "correct-horse-battery"); await page.fill("#lock-confirm", "correct-horse-battery");
  await page.click("#lock-form button[type=submit]");
  await page.waitForFunction(() => !document.getElementById("lock-dialog").open, null, { timeout: 20000 });
  check(await page.inputValue("#lock-passcode") === "" && await page.inputValue("#lock-confirm") === "", "the passphrase stayed in the closed lock form");
  const welcome = (await page.textContent("#welcome-message")).trim();
  log("welcome:", welcome);
  check(welcome === `Welcome, ${NAME}`, `the name was decoded wrongly: ${welcome}`);

  await page.click("#open-add"); await page.click("#open-uris"); await page.fill("#otp-uris", uris);
  await page.click("#uri-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 3, null, { timeout: 30000 });
  await page.waitForTimeout(1500);

  // 1. Conflict: the account changed on another device; this device's edit (made from the older version) is refused.
  await control("remoteTouch=1");
  const touched = (await control("")).mutations[0];
  await page.click("#edit-accounts");
  await page.fill("#entries .entry:first-child [data-field=issuer]", "Edited here");
  await page.click("#save-edits");
  await page.waitForTimeout(3000);
  let state = await control("");
  log("after a conflicting edit:", JSON.stringify(state.mutations), "| toast:", (await page.textContent("#toast")).trim());
  check(state.mutations[0] === touched, "an edit made from an older version overwrote the newer one");
  check(await page.evaluate(() => LockstepVault.pendingCount("user-1")) === 0, "the refused edit stayed in the upload queue");
  check(/changed on another device/.test(await page.textContent("#toast")), "the user was not told about the conflict");

  // 2. Deleted elsewhere: an edit of a removed account must not bring it back.
  check(!(await page.$$eval("#entries [data-field=issuer]", n => n.map(x => x.value))).includes("Edited here"), "the refused edit is still shown");
  await page.reload();
  await page.waitForFunction(() => !document.getElementById("locked").classList.contains("hidden") || document.querySelectorAll("#entries .entry:not(.entry-skel)").length > 0, null, { timeout: 15000 });
  if (await page.isVisible("#locked")) { await page.fill("#unlock-passcode", "correct-horse-battery"); await page.click("#unlock-form button[type=submit]"); }
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 3, null, { timeout: 20000 });
  await page.waitForTimeout(800);
  const lastId = await page.$eval("#entries .entry:last-child", n => n.dataset.id);
  await control("remoteDelete=1");
  await page.evaluate(async (id) => { await LockstepVault.updateEntry("user-1", id, "Renamed offline", "x@example.com"); }, lastId);
  await page.evaluate(() => loadEntries(true));
  await page.waitForTimeout(2500);
  state = await control("");
  log("after editing a deleted account:", state.entries.length, "accounts on the server");
  check(state.entries.length === 2, "an edit re-created a deleted account");
  check(await count(page) === 2, "the deleted account is still shown");

  // 3. A change the server refuses as invalid is dropped; the change after it is still uploaded.
  await page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => { const r = indexedDB.open("lockstep-vault"); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    const tx = db.transaction("outbox", "readwrite");
    tx.objectStore("outbox").put({ mutationId: crypto.randomUUID(), subject: "user-1", entryId: crypto.randomUUID(), operation: "PUT", createdAt: 1, attempts: 0,
      payload: { issuer: "Encrypted", accountName: "Encrypted", encryptedSecret: btoa("x".repeat(3000)), secretIv: btoa("123456789012"), keyVersion: 1, algorithm: "SHA1", digits: 6, periodSeconds: 30, createdAtEpochMillis: 1, mutationId: crypto.randomUUID() } });
    await new Promise((resolve) => { tx.oncomplete = resolve; });
    db.close();
  });
  await page.evaluate(() => addOtpUri("otpauth://totp/After:after@example.com?secret=NBSWY3DPO5XXE3DE&issuer=After", { synchronize: false }));
  await page.evaluate(() => loadEntries(true));
  await page.waitForTimeout(3000);
  state = await control("");
  log("after an invalid queued change:", state.entries.length, "accounts on the server | pending:", await page.evaluate(() => LockstepVault.pendingCount("user-1")));
  check(state.entries.length === 3, "a refused change blocked the next one");
  check(await page.evaluate(() => LockstepVault.pendingCount("user-1")) === 0, "the refused change is still queued");
  const tooLong = await page.evaluate(() => addOtpUri(`otpauth://totp/Long:l@example.com?secret=${"A".repeat(600)}&issuer=Long`).then(() => "saved", e => e.message));
  log("a 600-character secret:", tooLong);
  check(/too long/.test(tooLong), "an over-long secret was accepted");

  // 4. A damaged account is shown as an error; the others keep their codes.
  await page.evaluate(async () => {
    const db = await new Promise((resolve, reject) => { const r = indexedDB.open("lockstep-vault"); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    const store = db.transaction("entries", "readwrite").objectStore("entries");
    const all = await new Promise((resolve) => { const r = store.getAll(); r.onsuccess = () => resolve(r.result); });
    const victim = all.find(e => e.subject === "user-1");
    victim.secretIv = btoa("000000000000");
    await new Promise((resolve) => { const r = store.put(victim); r.onsuccess = resolve; });
    db.close();
  });
  await page.evaluate(() => refreshLocalCodes());
  await page.waitForTimeout(1500);
  const rows = await page.$$eval("#entries .entry", n => n.map(x => ({ broken: x.classList.contains("broken"), code: x.querySelector(".code")?.textContent || null })));
  log("rows with one damaged account:", JSON.stringify(rows));
  check(rows.filter(r => r.broken).length === 1 && rows.filter(r => !r.broken && /\d/.test(r.code || "")).length === rows.length - 1, "a damaged account hid the healthy ones");

  // 5. Focus survives a code change; an error message goes away by itself.
  await page.evaluate(() => loadEntries(true)); await page.waitForTimeout(1500);
  await page.focus("#entries .entry:not(.broken) [data-action=qr]");
  const before = await page.evaluate(() => document.activeElement?.closest(".entry")?.dataset.id);
  await page.waitForTimeout(16500);
  const after = await page.evaluate(() => document.activeElement?.closest(".entry")?.dataset.id);
  log("focused account before/after a code change:", before, after);
  check(before && before === after, "keyboard focus was lost when the codes changed");
  await page.evaluate(() => toast("Example error", true));
  await page.waitForTimeout(9000);
  check(!(await page.evaluate(() => document.getElementById("toast").classList.contains("visible"))), "an error message stayed on screen");

  const csp = await page.evaluate(() => window.__csp);
  check(csp.length === 0, `Content-Security-Policy / Trusted Types violations: ${csp}`);
  const realErrors = errors.filter(m => !m.startsWith("Failed to load resource"));
  check(realErrors.length === 0, `page errors: ${realErrors}`);
  log("CSP violations:", csp.length ? csp : "none", "| errors:", realErrors.length ? realErrors : "none");
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
