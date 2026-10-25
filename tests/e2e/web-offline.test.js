const API = `http://localhost:${process.env.API_PORT || 8080}`;
// Offline use of the web app (service worker on): reload offline, codes, rollover, unlock, add while offline, reconnect.
const { chromium } = require("playwright");
const [label, port] = [process.argv[2], process.argv[3]];
const base = `http://localhost:${port}/lockstep/`;
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const fakeJwt = `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Test User",email:"t@example.com",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const uris = ["JBSWY3DPEHPK3PXP","GEZDGNBVGY3TQOJQ"].map((s,i)=>`otpauth://totp/Issuer${i}:user${i}@example.com?secret=${s}&issuer=Issuer${i}&period=15`).join("\n");
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };

const count = (page) => page.$$eval("#entries .entry:not(.entry-skel)", n => n.length);
(async () => {
  await control("reset=1");
  const browser = await chromium.launch();
  const context = await browser.newContext({ acceptDownloads: true, serviceWorkers: "allow" });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType: "application/javascript", body: "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  await context.route("https://accounts.google.com/gsi/style", r => r.fulfill({ contentType: "text/css", body: "/* Google stylesheet fixture */" }));
  const page = await context.newPage();
  const errors = []; page.on("pageerror", e => errors.push(e.message));
  await page.goto(base); await page.waitForTimeout(1500);
  await page.evaluate(t => onGoogleCredential({ credential: t }), fakeJwt);
  await page.waitForSelector("#lock-dialog[open]");
  await page.fill("#lock-passcode", "abcd1234-long"); await page.fill("#lock-confirm", "abcd1234-long");
  await page.click("#lock-form button[type=submit]");
  await page.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await page.click("#open-add"); await page.click("#open-uris"); await page.fill("#otp-uris", uris);
  await page.click("#uri-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 2, null, { timeout: 20000 });
  await page.waitForTimeout(3000); // let the service worker finish caching

  await context.setOffline(true);
  const started = Date.now();
  await page.reload();
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 2 && document.getElementById("app-loading").classList.contains("hidden"), null, { timeout: 20000 });
  log(`offline reload: ${await count(page)} codes visible after ${Date.now() - started} ms; status: "${(await page.textContent("#account-summary")).trim()}"`);
  const before = await page.$$eval("#entries .entry .code", n => n.map(x => x.textContent));
  await page.waitForTimeout(16000);
  const after = await page.$$eval("#entries .entry .code", n => n.map(x => x.textContent));
  log("offline code rollover works:", before.some((c, i) => c !== after[i]));
  await page.click("#entries .entry [data-action=qr]");
  await page.waitForFunction(() => document.getElementById("qr-image").src.startsWith("data:image"), null, { timeout: 10000 });
  await page.click("#close-qr");
  log("offline QR code (lazy-loaded library): yes");

  await page.click("#lock-now"); await page.fill("#unlock-passcode", "abcd1234-long"); await page.click("#unlock-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 2, null, { timeout: 15000 });
  log("offline unlock with passkey: yes");

  await page.click("#open-add"); await page.click("#open-manual");
  await page.fill("#manual-issuer", "Offline add"); await page.fill("#manual-account", "me@example.com"); await page.fill("#manual-secret", "MFRGGZDFMZTWQ2LK");
  await page.click("#manual-form button[type=submit]");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 3, null, { timeout: 15000 });
  log(`added while offline: shown locally; server has ${(await control("")).entries.length} accounts; status: "${(await page.textContent("#account-summary")).trim()}"`);
  const offlineEditId=await page.evaluate(async()=>{
    const entry=(await LockstepVault.listEntries("user-1")).find(e=>e.issuer==="Issuer0");
    await LockstepVault.updateEntry("user-1",entry.id,"Edited offline",entry.accountName);
    await loadEntries(true);return entry.id;
  });
  check(await page.evaluate(()=>LockstepVault.pendingCount("user-1"))===2,"offline add and edit were not both retained in the queue");

  await control("clearCalls=1");
  await context.setOffline(false);
  await page.waitForFunction(async () => true);
  await page.waitForTimeout(4000);
  const state = await control("");
  log(`back online: server has ${state.entries.length} accounts; calls: ${JSON.stringify(state.calls)}; status: "${(await page.textContent("#account-summary")).trim()}"`);
  check(state.entries.length === 3, "offline change was not uploaded");
  const editSynced=await page.evaluate(async id=>{
    const local=(await LockstepVault.localEncryptedEntries("user-1")).find(e=>e.id===id);
    const remote=(await api("/api/v1/entries")).find(e=>e.id===id);
    return remote?.encryptedLabel===local.encryptedLabel&&remote?.mutationId===local.mutationId&&await LockstepVault.pendingCount("user-1")===0;
  },offlineEditId);
  check(editSynced,"reconnection did not upload the offline edit and clear the acknowledged queue");
  log("offline add and edit both reached the server automatically");
  check(errors.length === 0, `page errors: ${errors}`);
  log("errors:", errors.length ? errors : "none");
  await browser.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
