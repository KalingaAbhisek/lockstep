// Extension regressions: a lock pressed while an unlock is still running wins, a silently renewed Google token
// does not count as a recent sign-in, the session key is kept sealed, a damaged account does not hide the
// others, and the sync queue survives a refused change. Usage: node extension-integrity.test.js <label> <extensionDir>
const API = `http://localhost:${process.env.API_PORT || 8080}`;
const { chromium } = require("playwright");
const [label, extDir] = [process.argv[2], process.argv[3]];
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const token = () => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Test User",email:"t@example.com",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };
const PASS = "correct-horse-battery";

(async () => {
  await control("reset=1");
  await fetch(`${API}/api/v1/session`, { method: "POST" });
  const context = await chromium.launchPersistentContext(require("path").join(require("os").tmpdir(), `lockstep-profile-${label}-${Date.now()}`), {
    channel: "chromium", headless: true,
    ignoreDefaultArgs: ["--disable-extensions"], args: ["--headless=new", `--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`] });
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const extensionId = worker.url().split("/")[2];
  for (let i = 0; i < 100; i++) {
    if (await worker.evaluate(() => Boolean(globalThis.chrome?.storage) && typeof setTimeout === "function").catch(() => false)) break;
    await new Promise(r => setTimeout(r, 100));
  }
  await worker.evaluate(async ({ token, pass }) => {
    await chrome.storage.local.set({ vaultSubject: "user-1", vaultDisplayName: "Test User", appSessionId: "session-token", appSessionExpiry: Date.now() + 864e5 });
    await chrome.storage.session.set({ idToken: token, tokenExpiry: Date.now() + 3600e3, interactiveSignInAt: Date.now(), newAccountSetupAuthorized: true });
    await setLockConfig(pass, 300, false, true);
    await importEntries(["JBSWY3DPEHPK3PXP", "GEZDGNBVGY3TQOJQ", "MFRGGZDFMZTWQ2LK"].map((s, i) => `otpauth://totp/I${i}:u${i}@example.com?secret=${s}&issuer=I${i}`));
  }, { token: token(), pass: PASS });

  // 1. Lock pressed while an unlock is still deriving the key (Argon2id takes a moment): the lock wins.
  const race = await worker.evaluate(async (pass) => {
    await lockVault();
    const unlocking = verifyLock(pass).then(() => "unlocked", (error) => error.code || error.message);
    await new Promise(r => setTimeout(r, 30));
    await lockVault();
    const outcome = await unlocking;
    return { outcome, unlocked: LockstepVault.isUnlocked("user-1"), stored: Boolean((await chrome.storage.session.get("unlockedMaster")).unlockedMaster) };
  }, PASS);
  log("unlock interrupted by a lock:", JSON.stringify(race));
  check(!race.unlocked && race.outcome !== "unlocked" && !race.stored, "an unlock that was still running undid the lock");

  // 2. The kept vault key is sealed (no readable key in session storage) and still restores after a worker restart.
  const sealed = await worker.evaluate(async (pass) => {
    await verifyLock(pass);
    const { unlockedMaster } = await chrome.storage.session.get("unlockedMaster");
    LockstepVault.lock("user-1");
    const resumed = await resumeVault();
    return { hasRaw: Boolean(unlockedMaster?.snapshot?.raw), hasSealed: Boolean(unlockedMaster?.snapshot?.sealed), resumed };
  }, PASS);
  log("session key:", JSON.stringify(sealed));
  check(!sealed.hasRaw && sealed.hasSealed && sealed.resumed, "the unlocked vault key is not kept sealed, or could not be resumed");

  // 3. Only a sign-in the user completed counts as recent; a silently renewed token does not.
  const recent = await worker.evaluate(async () => {
    const withInteractive = await hasRecentGoogleSignIn();
    await chrome.storage.session.remove("interactiveSignInAt");
    const silentOnly = await hasRecentGoogleSignIn();
    let reset; try { await resetVault("RESET"); reset = "reset"; } catch (error) { reset = error.code; }
    return { withInteractive, silentOnly, reset };
  });
  log("recent sign-in:", JSON.stringify(recent));
  check(recent.withInteractive && !recent.silentOnly && recent.reset === "REAUTH_REQUIRED", "a silently renewed Google token allowed a vault reset");
  check((await control("")).resets === 0, "the vault was reset without a Google confirmation");

  // 4. A damaged account is listed as an error; the others keep their codes.
  const rows = await worker.evaluate(async () => {
    const db = await new Promise((resolve, reject) => { const r = indexedDB.open("lockstep-vault"); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    const store = db.transaction("entries", "readwrite").objectStore("entries");
    const all = await new Promise((resolve) => { const r = store.getAll(); r.onsuccess = () => resolve(r.result); });
    const victim = all.find(e => e.subject === "user-1");
    victim.secretIv = btoa("000000000000");
    await new Promise((resolve) => { const r = store.put(victim); r.onsuccess = resolve; });
    return (await localEntries()).map(e => ({ error: Boolean(e.error), code: e.code }));
  });
  log("entries with one damaged account:", JSON.stringify(rows));
  check(rows.filter(r => r.error).length === 1 && rows.filter(r => !r.error && /^\d{6}$/.test(r.code)).length === 2, "a damaged account hid the healthy ones");

  // The popup shows the damaged row and the healthy codes.
  const page = await context.newPage();
  const errors = []; page.on("pageerror", e => errors.push(e.message));
  await page.goto(`chrome-extension://${extensionId}/popup.html`);
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length === 3, null, { timeout: 20000 });
  const shown = await page.$$eval("#entries .entry", n => n.map(x => x.classList.contains("broken")));
  check(shown.filter(Boolean).length <= 1, "the popup did not render the account list");
  { // An account damaged on the server (first in the list) must not break the countdowns of the healthy ones.
    await worker.evaluate(async () => {
      const row = (await LockstepVault.localEncryptedEntries("user-1"))[0]; const { storageId, subject, ...wire } = row;
      await api(`/api/v1/entries/${row.id}`, { method: "PUT", body: JSON.stringify({ ...wire, encryptedSecret: btoa("x".repeat(40)), mutationId: crypto.randomUUID(), baseMutationId: row.mutationId }) });
      await synchronize();
    });
    await page.evaluate(() => load(true));
    await page.waitForFunction(() => document.querySelector("#entries .entry.broken"), null, { timeout: 10000 });
    await page.waitForTimeout(600);
    const countdowns = await page.$$eval("#entries .entry:not(.broken) .countdown", n => n.map(x => x.textContent));
    log("healthy countdowns next to a damaged account:", JSON.stringify(countdowns));
    check(countdowns.length === 2 && countdowns.every(text => /^\d+s$/.test(text)), `countdowns broken by a damaged account: ${JSON.stringify(countdowns)}`);
  }
  const version = (await page.textContent("#settings-version")).trim();
  check(/^Lockstep \d+\.\d+\.\d+$/.test(version), `the version shown is not read from the manifest: ${version}`);

  // Actual popup rendering: three actions must leave room for a long issuer and an eight-digit code.
  const layout = await page.evaluate(() => {
    const saved=entries;
    entries=[{...saved.find(e=>!e.error),issuer:"Long issuer ".repeat(10),accountName:"Long account ".repeat(20),localOnly:true,canRetry:true,code:"12345678"}];
    renderEntries();
    const row=document.querySelector("#entries .entry"), issuer=row.querySelector(".issuer").getBoundingClientRect(), actions=row.querySelector(".entry-actions").getBoundingClientRect();
    const okay=issuer.right<=actions.left && row.scrollWidth<=row.clientWidth;
    entries=saved;renderEntries();return okay;
  });
  check(layout,"a long issuer or eight-digit code overlapped the third action or overflowed the popup");
  await page.waitForFunction(() => !refreshing);
  const popupRace = await page.evaluate(async () => {
    const originalSend = chrome.runtime.sendMessage.bind(chrome.runtime);
    let release, reached;
    const ready = new Promise(resolve => reached = resolve);
    chrome.runtime.sendMessage = async message => {
      const result = await originalSend(message);
      if (message.type === "LIST_ENTRIES") {
        reached();
        return new Promise(resolve => release = () => resolve(result));
      }
      return result;
    };
    try {
      const loading = load(true);
      await Promise.race([ready, new Promise((_, reject) => setTimeout(() => reject(new Error("Delayed list did not start")), 15000))]);
      await lockAuthenticator();
      release();
      await loading;
      return { locked: !$("locked").classList.contains("hidden"), rows: $("entries").childElementCount, retained: entries.length, drafts: originalEntries.size };
    } finally { chrome.runtime.sendMessage = originalSend; }
  });
  check(popupRace.locked && popupRace.rows === 0 && popupRace.retained === 0 && popupRace.drafts === 0, "a delayed decrypted response repopulated the locked popup");
  await worker.evaluate(pass => verifyLock(pass), PASS);
  await page.evaluate(() => showSignedIn());
  log("delayed list reply after lock:", JSON.stringify(popupRace));
  await require("./render-performance")(page,"extension");
  await require("./render-performance").verifyLongConfirmation(page,"extension");
  const qr=await page.evaluate(async()=>{
    const original=window.jsQR;let dimensions;
    try{window.jsQR=(data,width,height)=>{dimensions={width,height,bytes:data.byteLength};return null};
      const image=document.createElement("canvas");image.width=3200;image.height=2400;detectQrImage(image);
    }finally{window.jsQR=original;}
    const bitmap=createImageBitmap;let closed=false;
    try{window.createImageBitmap=async()=>({width:10000,height:10000,close:()=>closed=true});
      await importQrImages({target:{files:[{size:100}],value:""}});
    }finally{window.createImageBitmap=bitmap;}
    return {...dimensions,closed};
  });
  check(qr.width===1600&&qr.height===1200&&qr.bytes===7_680_000&&qr.closed,"QR decoding exceeded its pixel bound or leaked a refused bitmap");

  // 5. A queued change the server refuses for good is dropped, and the next change still uploads. The popup is
  // closed first: an open popup shows the notice itself and clears it, which would race with this check.
  await page.close();
  const queue = await worker.evaluate(async () => {
    const db = await new Promise((resolve, reject) => { const r = indexedDB.open("lockstep-vault"); r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
    const tx = db.transaction("outbox", "readwrite");
    tx.objectStore("outbox").put({ mutationId: crypto.randomUUID(), subject: "user-1", entryId: crypto.randomUUID(), operation: "PUT", createdAt: 1, attempts: 0,
      payload: { issuer: "Encrypted", accountName: "Encrypted", encryptedSecret: btoa("x".repeat(3000)), secretIv: btoa("123456789012"), keyVersion: 1, algorithm: "SHA1", digits: 6, periodSeconds: 30, createdAtEpochMillis: 1, mutationId: crypto.randomUUID() } });
    await new Promise((resolve) => { tx.oncomplete = resolve; });
    await addOtpUri("otpauth://totp/After:after@example.com?secret=NBSWY3DPO5XXE3DE&issuer=After");
    // A background retry may be the flush that met the refusal; its notice lands a moment later.
    let syncNotice = null;
    for (let i = 0; i < 50 && !syncNotice; i++) { ({ syncNotice } = await chrome.storage.session.get("syncNotice")); if (!syncNotice) await new Promise(r => setTimeout(r, 100)); }
    return { pending: await LockstepVault.pendingCount("user-1"), notice: syncNotice || null, syncError: lastSyncError };
  });
  const server = await control("");
  log("after a refused queued change:", JSON.stringify(queue), JSON.stringify(server.entries));
  check(queue.pending === 0 && server.entries.length === 4, "a refused change blocked the queue");
  check(Boolean(queue.notice), "the user is not told about the refused change");

  // 6. Deletion needs both the passphrase and an interactive Google confirmation. A failed request
  // leaves the local account visible; an acknowledged deletion clears it and cannot be replayed.
  const deletion = await worker.evaluate(async pass => {
    const entry = (await localEntries()).find(e => !e.error);
    let wrong, oldGoogle, failed;
    try { await deleteEntry(entry.id, "incorrect-passphrase"); } catch(e) { wrong=e.code; }
    try { await deleteEntry(entry.id, pass); } catch(e) { oldGoogle=e.code; }
    await chrome.storage.session.set({interactiveSignInAt:Date.now()});
    const originalApi = api;
    api = async (path, options) => { if(options?.method==="DELETE") throw new Error("Simulated unavailable server"); return originalApi(path,options); };
    try { await deleteEntry(entry.id, pass); } catch(e) { failed=e.message; } finally { api=originalApi; }
    const kept=(await localEntries()).some(e=>e.id===entry.id);
    const payload=(await LockstepVault.localEncryptedEntries("user-1")).find(e=>e.id===entry.id);
    await deleteEntry(entry.id,pass);
    let replay; try { await api(`/api/v1/entries/${entry.id}`,{method:"PUT",body:JSON.stringify(payload)}); replay="accepted"; } catch(e) { replay=e.code; }
    return {wrong,oldGoogle,failed,kept,replay,gone:!(await localEntries()).some(e=>e.id===entry.id)};
  },PASS);
  log("confirmed deletion:", JSON.stringify(deletion));
  check(deletion.wrong==="WRONG_PASSKEY" && deletion.oldGoogle==="REAUTH_REQUIRED" && deletion.kept && deletion.gone && deletion.replay==="DELETED", "confirmed deletion failed or lost an account before acknowledgement");

  const reset = await worker.evaluate(async pass => {
    // No passphrase is asked (it is for someone who lost it); the typed word RESET is required.
    let wrong;try { await resetVault("incorrect-passphrase"); } catch(e) {wrong=e.message;}
    const kept=(await localEntries()).length;
    await resetVault("RESET");
    return {wrong,kept,remaining:(await LockstepVault.localEncryptedEntries("user-1")).length};
  },PASS);
  check(/Type RESET/.test(reset.wrong||"") && reset.kept===3 && reset.remaining===0 && (await control("")).resets===1,"vault reset did not require typing RESET or left local data behind");

  check(errors.length === 0, `page errors: ${errors}`);
  log("errors:", errors.length ? errors : "none");
  await context.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
