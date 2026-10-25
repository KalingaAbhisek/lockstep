const API = `http://localhost:${process.env.API_PORT || 8080}`;
const { chromium } = require("playwright");
const [label, extDir] = [process.argv[2], process.argv[3]];
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
// A Google ID token issued just now (the mock checks only its claims), so key-changing actions are allowed.
const freshGoogleToken = () => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Test User",email:"t@example.com",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };

const uris = ["JBSWY3DPEHPK3PXP","GEZDGNBVGY3TQOJQ"].map((s,i)=>`otpauth://totp/Issuer${i}:user${i}@example.com?secret=${s}&issuer=Issuer${i}&period=15`);
(async () => {
  await control("reset=1"); await fetch(`${API}/api/v1/session`, { method: "POST" });
  const context = await chromium.launchPersistentContext(require("path").join(require("os").tmpdir(), `lockstep-profile-${label}-${Date.now()}`), {
    channel: "chromium", headless: true, ignoreDefaultArgs: ["--disable-extensions"],
    args: ["--headless=new", `--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`] });
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  // Wait from here until the worker has started (asking too early can run before its timers exist).
  for (let i = 0; i < 100; i++) {
    if (await worker.evaluate(() => Boolean(globalThis.chrome?.storage) && typeof setTimeout === "function").catch(() => false)) break;
    await new Promise(r => setTimeout(r, 100));
  }
  const id = worker.url().split("/")[2];
  await worker.evaluate(async ({ uris, token }) => {
    await chrome.storage.local.set({ vaultSubject: "user-1", vaultDisplayName: "Test", appSessionId: "session-token", appSessionExpiry: Date.now() + 864e5 });
    await chrome.storage.session.set({ idToken: token, tokenExpiry: Date.now() + 3600e3, interactiveSignInAt: Date.now() });
    await chrome.storage.session.set({ newAccountSetupAuthorized: true });
    await setLockConfig("1234pass-long", 300, false, true); await importEntries(uris);
  }, { uris, token: freshGoogleToken() });
  await control("down=1"); // API unreachable from now on
  const page = await context.newPage(); const errors = []; page.on("pageerror", e => errors.push(e.message));
  const started = Date.now();
  await page.goto(`chrome-extension://${id}/popup.html`);
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 2, null, { timeout: 20000 });
  log(`API down: popup shows 2 codes after ${Date.now() - started} ms`);
  const before = await page.$$eval("#entries .entry .code", n => n.map(x => x.textContent));
  await page.waitForTimeout(16000);
  const after = await page.$$eval("#entries .entry .code", n => n.map(x => x.textContent));
  log("code rollover with API down:", before.some((c, i) => c !== after[i]));
  await page.click("#entries .entry [data-action=qr]");
  await page.waitForFunction(() => document.getElementById("qr-image").src.startsWith("data:image"), null, { timeout: 10000 });
  log("QR code with API down: yes");
  const offline = await worker.evaluate(async () => {
    await lockVault();
    let wrong; try { await verifyLock("wrong-pass"); wrong = "unlocked?!"; } catch (e) { wrong = e.message; }
    const right = (await verifyLock("1234pass-long")).unlocked;
    await addOtpUri("otpauth://totp/Offline:o@example.com?secret=MFRGGZDFMZTWQ2LK&issuer=Offline");
    return { wrong, right, local: (await localEntries()).length, pending: await LockstepVault.pendingCount(await subject()) };
  });
  log("API down: unlock/add:", JSON.stringify(offline), "| server accounts:", (await control("")).entries.length);
  await control("down=0"); await control("clearCalls=1");
  // API recovery does not emit an online event. First prove cooldown keeps the upload queued,
  // then advance its deadline to exercise recovery without waiting minutes in CI.
  await worker.evaluate(async () => { await retryPendingSync(); });
  check((await control("")).entries.length === 2, "retry ignored the outage cooldown");
  await worker.evaluate(async () => { for(const retry of syncRetryStates.values())retry.until=Date.now()-1; await retryPendingSync(); });
  const st = await control("");
  check(st.entries.length === 3, "queued change was not uploaded");
  log(`API back: server accounts ${st.entries.length}; calls ${JSON.stringify(st.calls)}`);
  // Real browser offline/online transition, with the popup closed and vault locked:
  // the encrypted outbox must upload without reopening, unlocking, or invoking retry manually.
  await control("down=1");await context.setOffline(true);
  await worker.evaluate(async()=>{
    await addOtpUri("otpauth://totp/Reconnect:closed-popup?secret=NBSWY3DPO5XXE3DE&issuer=Reconnect");
    await lockVault();
  });
  check(await worker.evaluate(()=>LockstepVault.pendingCount("user-1"))===1,"reconnect fixture did not retain its offline change");
  await page.close();
  await control("down=0");
  const reconnectedAt=Date.now();await context.setOffline(false);
  let restored;
  for(let i=0;i<75;i++){
    restored=await control("");if(restored.entries.length===4)break;
    await new Promise(resolve=>setTimeout(resolve,200));
  }
  check(restored.entries.length===4,"browser reconnection did not automatically upload with the popup closed");
  check(await worker.evaluate(()=>LockstepVault.pendingCount("user-1"))===0,"reconnection left an acknowledged change queued");
  log(`browser reconnected: popup closed, vault locked; auto-upload after ${Date.now()-reconnectedAt} ms`);
  await worker.evaluate(()=>verifyLock("1234pass-long"));
  const reopenedPage=await context.newPage();reopenedPage.on("pageerror",e=>errors.push(e.message));
  await reopenedPage.goto(`chrome-extension://${id}/popup.html`);
  await reopenedPage.waitForFunction(()=>document.querySelectorAll("#entries .entry:not(.entry-skel)").length===4);
  await context.setOffline(true);await control("down=1");
  await worker.evaluate(()=>addOtpUri("otpauth://totp/Immediate:open-popup?secret=KRSXG5BAMFZGK3TP&issuer=Immediate"));
  const offlineEditId=await worker.evaluate(async()=>{
    const entry=(await localEntries()).find(e=>e.issuer==="Issuer0");
    await updateEntry(entry.id,"Edited offline",entry.accountName);return entry.id;
  });
  check(await worker.evaluate(()=>LockstepVault.pendingCount("user-1"))===2,"extension did not retain both the offline add and edit");
  await control("down=0");const openReconnectAt=Date.now();await context.setOffline(false);
  for(let i=0;i<25;i++){
    restored=await control("");if(restored.entries.length===5)break;
    await new Promise(resolve=>setTimeout(resolve,200));
  }
  check(restored.entries.length===5,"open popup did not trigger an immediate reconnect upload");
  check(await worker.evaluate(()=>LockstepVault.pendingCount("user-1"))===0,"open-popup reconnect left queued work behind");
  check(await worker.evaluate(async id=>{
    const local=(await LockstepVault.localEncryptedEntries("user-1")).find(e=>e.id===id);
    const remote=(await api("/api/v1/entries")).find(e=>e.id===id);
    return local?.encryptedLabel===remote?.encryptedLabel&&local?.mutationId===remote?.mutationId;
  },offlineEditId),"extension offline edit was not uploaded on reconnect");
  log(`browser reconnected: popup open; auto-upload after ${Date.now()-openReconnectAt} ms`);
  log("errors:", errors.length ? errors : "none");
  await context.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
