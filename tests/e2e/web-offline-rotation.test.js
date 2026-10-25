// An account added offline on one device while the recovery key is rotated on another must not be lost:
// the server refuses it (STALE_KEY), this device keeps it ("Only on this device") and, after the next unlock,
// re-encrypts it with the new key and uploads it. Also: a refused account can be uploaded again, and the
// recovery form never keeps the recovery key or new passphrase. Usage: node web-offline-rotation.test.js <label> <port>
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
const codes = (page) => page.$$eval("#entries .entry:not(.entry-skel)", n => n.map(x => ({ broken: x.classList.contains("broken"), localOnly: Boolean(x.querySelector(".local-only-label")), code: x.querySelector(".code")?.textContent || null })));
const waitCount = (page, n) => page.waitForFunction(c => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === c, n, { timeout: 30000 });

async function device(browser) {
  const context = await browser.newContext({ acceptDownloads: true, serviceWorkers: "block" });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType: "application/javascript", body: "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  const page = await context.newPage();
  page.errors = []; page.on("pageerror", e => page.errors.push(e.message));
  await page.goto(base); await page.waitForTimeout(800);
  await page.evaluate(t => onGoogleCredential({ credential: t }), jwt());
  return { page, context };
}
async function unlock(page) {
  await page.waitForSelector("#locked:not(.hidden)", { timeout: 15000 });
  await page.fill("#unlock-passcode", P); await page.click("#unlock-form button[type=submit]");
}
async function addManual(page, issuer, secret) {
  await page.click("#open-add"); await page.click("#open-manual");
  await page.fill("#manual-issuer", issuer); await page.fill("#manual-account", `${issuer.toLowerCase()}@x.com`); await page.fill("#manual-secret", secret);
  await page.click("#manual-form button[type=submit]");
}

(async () => {
  await control("reset=1");
  const browser = await chromium.launch();
  const { page: a, context: ac } = await device(browser);
  await a.waitForSelector("#lock-dialog[open]");
  await a.fill("#lock-passcode", P); await a.fill("#lock-confirm", P); await a.click("#lock-form button[type=submit]");
  await a.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await addManual(a, "Alpha", "JBSWY3DPEHPK3PXP"); await waitCount(a, 1); await a.waitForTimeout(1500);

  // Recovery form: values never stay after going back.
  await a.click("#lock-now"); await a.click("#forgot-passkey");
  await a.fill("#restore-key", "LS2-M-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"); await a.fill("#restore-passcode", "a-new-passphrase-1");
  await a.click("#restore-back");
  const leftover = await a.evaluate(() => [document.getElementById("restore-key").value, document.getElementById("restore-passcode").value].join(""));
  check(leftover === "", "the recovery key or new passphrase stayed in the hidden recovery form");
  await unlock(a); await waitCount(a, 1);

  // Device A goes offline and adds an account; device B rotates the recovery key meanwhile.
  await ac.setOffline(true);
  await addManual(a, "Offline", "GEZDGNBVGY3TQOJQ"); await waitCount(a, 2);
  const { page: b } = await device(browser);
  await unlock(b); await waitCount(b, 1);
  await b.evaluate(t => { state.token = t; }, jwt());
  await b.click("#open-settings"); await b.click("#settings-key-rotate");
  await b.waitForSelector("#confirm-dialog[open]"); await b.fill("#confirm-passkey", P); await b.click("#confirm-accept");
  await b.waitForFunction(() => /rotated|could not|refused/i.test(document.getElementById("toast").textContent), null, { timeout: 30000 });
  log("device B:", (await b.textContent("#toast")).trim(), "| server key version:", (await control("")).keyVersion);

  // Device A comes back online: the upload is refused (old key), but the account stays on the device.
  await ac.setOffline(false);
  await a.evaluate(() => window.dispatchEvent(new Event("online")));
  await a.waitForTimeout(4000);
  const afterRefusal = await a.evaluate(async () => ({ pending: await LockstepVault.pendingCount("user-1"), local: (await LockstepVault.localEncryptedEntries("user-1")).length }));
  log("device A after the refused upload:", JSON.stringify(afterRefusal), "| server accounts:", (await control("")).entries.length);
  check(afterRefusal.local === 2, "the account added offline was deleted from device A");

  // After the next unlock it is re-encrypted with the new key and uploaded.
  await a.waitForSelector("#locked:not(.hidden)"); await unlock(a); await waitCount(a, 2);
  await a.waitForTimeout(4000);
  let st = await control("");
  const rows = await codes(a);
  log("device A after unlocking:", JSON.stringify(rows), "| server accounts:", st.entries.length, "| toast:", (await a.textContent("#toast")).trim());
  check(st.entries.length === 2, "the account added offline never reached the server");
  check(rows.every(r => !r.broken && !r.localOnly && /\d/.test(r.code || "")), "the rescued account cannot be opened, or is still only on this device");
  await b.click("#lock-now"); await unlock(b); await waitCount(b, 2);
  check((await codes(b)).every(r => !r.broken), "device B cannot open the rescued account");
  await b.waitForTimeout(500);

  // Same, but the passphrase was also changed on the other device: the account asks for the previous passphrase.
  const P2 = "second-passphrase-2";
  await ac.setOffline(true);
  await addManual(a, "Offline two", "ONSWG4TFOQYTEMZU"); await waitCount(a, 3);
  await b.evaluate(t => { state.token = t; }, jwt());
  await b.click("#open-settings"); await b.click("#settings-key-rotate");
  await b.waitForSelector("#confirm-dialog[open]"); await b.fill("#confirm-passkey", P); await b.click("#confirm-accept");
  await b.waitForFunction(() => /rotated to version 3/.test(document.getElementById("toast").textContent), null, { timeout: 30000 });
  await b.evaluate(t => { state.token = t; }, jwt());
  await b.click("#open-settings"); await b.click("#settings-lock"); await b.waitForSelector("#lock-dialog[open]");
  await b.fill("#lock-passcode", P2); await b.fill("#lock-confirm", P2); await b.click("#lock-form button[type=submit]");
  await b.waitForFunction(() => !document.getElementById("lock-dialog").open, null, { timeout: 30000 });
  await ac.setOffline(false); await a.evaluate(() => window.dispatchEvent(new Event("online"))); await a.waitForTimeout(3000);
  await a.waitForSelector("#locked:not(.hidden)");
  await a.fill("#unlock-passcode", P2); await a.click("#unlock-form button[type=submit]"); await waitCount(a, 3); await a.waitForTimeout(2000);
  const needs = await a.$$eval("#entries [data-action=rescue]", n => n.length);
  log("accounts asking for the previous passphrase:", needs, "| local accounts:", await a.evaluate(async () => (await LockstepVault.localEncryptedEntries("user-1")).length));
  check(needs === 1, "the account added offline does not offer to open with the previous passphrase");
  if (needs) {
    await a.click("#entries [data-action=rescue]"); await a.waitForSelector("#confirm-dialog[open]");
    await a.fill("#confirm-passkey", P); await a.click("#confirm-accept"); await a.waitForTimeout(4000);
    st = await control("");
    log("after opening it with the previous passphrase:", st.entries.length, "server accounts | rows:", JSON.stringify(await codes(a)));
    check(st.entries.length === 3 && (await codes(a)).every(r => !r.broken && !r.localOnly), "the previous passphrase did not recover the account");
  }

  // A new account the server refuses is kept ("Only on this device"), not counted as synchronized, and can be uploaded again.
  await control("limitNextAdd=1");
  await addManual(a, "Refused", "MFRGGZDFMZTWQ2LK"); await waitCount(a, 4); await a.waitForTimeout(3000);
  await a.evaluate(() => loadEntries(true)); await a.waitForTimeout(1500);
  const summary = (await a.textContent("#account-summary")).trim();
  log("summary with a refused account:", summary, "| rows:", JSON.stringify(await codes(a)));
  check(/3 synchronized accounts · 1 only on this device/.test(summary), `the refused account is counted as synchronized: ${summary}`);
  check((await codes(a)).filter(r => r.localOnly).length === 1, "the refused account is not marked \"Only on this device\"");
  await a.click("#entries [data-action=retry-upload]"); await a.waitForTimeout(3500);
  st = await control("");
  log("after uploading it again:", st.entries.length, "server accounts | summary:", (await a.textContent("#account-summary")).trim());
  check(st.entries.length === 4 && (await codes(a)).every(r => !r.localOnly), "uploading the refused account again failed");

  const errors = [...a.errors, ...b.errors];
  check(errors.length === 0, `page errors: ${errors}`);
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
