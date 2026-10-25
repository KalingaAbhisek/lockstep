const API = `http://localhost:${process.env.API_PORT || 8080}`;
// Passphrase suggestion, encrypted names, atomic rotation (incl. a refused one), reload, server sign-out.
const { chromium } = require("playwright");
const [label, port] = [process.argv[2], process.argv[3]];
const base = `http://localhost:${port}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJwt = `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Test User",email:"t@example.com",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const uris = ["JBSWY3DPEHPK3PXP","GEZDGNBVGY3TQOJQ","MFRGGZDFMZTWQ2LK"].map((s,i)=>`otpauth://totp/Issuer${i}:user${i}@example.com?secret=${s}&issuer=Issuer${i}`).join("\n");
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };

const names = (page) => page.$$eval("#entries .entry:not(.entry-skel) .issuer", n => n.map(x => x.textContent));
const codes = (page) => page.$$eval("#entries .entry .code", n => n.map(x => x.textContent));
async function rotate(page, passphrase) {
  await page.click("#open-settings"); await page.click("#settings-key-rotate");
  await page.waitForSelector("#confirm-dialog[open]");
  await page.fill("#confirm-passkey", passphrase); await page.click("#confirm-accept");
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
  const downloads = []; page.on("download", d => downloads.push(d.suggestedFilename()));
  await page.goto(base); await page.waitForTimeout(1000);
  await page.evaluate(t => onGoogleCredential({ credential: t }), fakeJwt);
  await page.waitForSelector("#lock-dialog[open]");
  await page.fill("#lock-passcode", "short-pass1");
  log("11-char strength label:", (await page.textContent("#lock-strength")).trim());
  await page.click("#lock-suggest");
  const suggested = await page.inputValue("#lock-passcode");
  log("suggested passphrase:", suggested, "| label:", (await page.textContent("#lock-strength")).trim(), "| confirm filled:", (await page.inputValue("#lock-confirm")) === suggested);
  await page.click("#lock-form button[type=submit]");
  await page.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await page.click("#open-add"); await page.click("#open-uris"); await page.fill("#otp-uris", uris);
  await page.click("#uri-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 3, null, { timeout: 20000 });
  await page.waitForTimeout(1500);
  let st = await control("");
  check(st.encrypted === 3, "account names were not encrypted on the server");
  check(JSON.stringify(await names(page)) === JSON.stringify(["Issuer0", "Issuer1", "Issuer2"]), "account names were not shown decrypted");
  log("names on screen:", JSON.stringify(await names(page)), "| names on server:", JSON.stringify(st.entries), "| encrypted:", st.encrypted);
  log("session storage:", await page.evaluate(() => Object.keys(localStorage).filter(k => k.startsWith("authsync.appSession.web.")).map(k => localStorage.getItem(k))[0]));

  // A rotation the server refuses (vault changed): nothing may change anywhere.
  const before = await codes(page);
  await control("conflictNextRotate=1");
  await rotate(page, suggested);
  await page.waitForTimeout(4000);
  st = await control("");
  check(st.keyVersion === 1, "a refused rotation changed the server");
  log("refused rotation toast:", (await page.textContent("#toast")).trim(), "| server key version:", st.keyVersion, "| codes unchanged:", JSON.stringify(await codes(page)) === JSON.stringify(before));

  // A successful rotation.
  // Reproduce local revision 4 / server revision 3, same master but different wrappers.
  // Rotation must verify the master matches and repair metadata before submitting its expected revision.
  await control("advanceVaultRevision=1");
  await control("advanceVaultRevision=1");
  await page.evaluate(async passphrase => {
    const owner = ownerSubject();
    await LockstepVault.configurePassphrase(owner, passphrase);
    await LockstepVault.markWrappedKeySynced(owner, 4, await LockstepVault.exportWrappedKey(owner));
  }, suggested);
  await control("clearCalls=1");
  await rotate(page, suggested);
  await page.waitForFunction(() => /rotated to version/.test(document.getElementById("toast").textContent), null, { timeout: 20000 });
  st = await control("");
  check(st.keyVersion === 2, "rotation did not reach the server");
  log("rotation:", (await page.textContent("#toast")).trim(), "| server key version:", st.keyVersion, "| calls:", JSON.stringify(st.calls.filter(c => !c.startsWith("GET"))), "| downloads:", JSON.stringify(downloads));
  log("names after rotation:", JSON.stringify(await names(page)), "| codes same:", JSON.stringify(await codes(page)) === JSON.stringify(before) ? "yes (same 30s window)" : "changed (window passed)");

  await page.reload();
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 3, null, { timeout: 20000 });
  log("after reload:", JSON.stringify(await names(page)));
  await page.click("#lock-now"); await page.fill("#unlock-passcode", suggested); await page.click("#unlock-form button[type=submit]");
  // Unlocking an Argon2id-protected key (64 MiB) can take several seconds on a busy machine.
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 3, null, { timeout: 30000 });
  log("unlock after rotation: yes");

  await control("clearCalls=1");
  await page.click("#sign-out");
  await page.click("#confirm-cancel");
  check(await page.evaluate(()=>Boolean(state.subject)), "cancelled sign-out changed the session");
  await page.click("#sign-out");
  await page.click("#confirm-accept");
  await page.waitForSelector("#signed-out:not(.hidden)");
  await page.waitForTimeout(1500);
  st = await control("");
  check(st.session === null, "sign-out did not end the server session");
  const removed=await page.evaluate(async()=>({entries:(await LockstepVault.localEncryptedEntries("user-1")).length,key:await LockstepVault.keyState("user-1"),pending:await LockstepVault.pendingCount("user-1")}));
  check(removed.entries===0&&removed.key==="none"&&removed.pending===0,"sign-out retained local vault data");
  check(st.entries.length>0,"sign-out removed server entries");
  log("sign-out calls:", JSON.stringify(st.calls), "| server session after sign-out:", st.session);
  log("cookie sessions:", st.cookieSessions, "| CSP violations:", JSON.stringify(await page.evaluate(() => window.__csp)));
  check(errors.length === 0, `page errors: ${errors}`);
  log("errors:", errors.length ? errors : "none");
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
