// Confirmed deletion, failed requests, create replays, and upgrading the existing IndexedDB data.
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const API = `http://localhost:${process.env.API_PORT || 8080}`;
const [label, port] = process.argv.slice(2);
const base = `http://localhost:${port}/lockstep/`;
const PASS = "correct-horse-battery";
const b64 = o => Buffer.from(JSON.stringify(o)).toString("base64url");
const token = (age = 0) => { const iat = Math.floor(Date.now()/1000)-age; return `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Test",iat,exp:iat+3600})}.sig`; };
const control = () => fetch(`${API}/__control`).then(r => r.json());
(async () => {
  await fetch(`${API}/__control?reset=1`);
  const browser = await chromium.launch();
  const context = await browser.newContext({serviceWorkers:"block"});
  await context.route("https://accounts.google.com/**", r => r.fulfill({contentType:"application/javascript",body:"window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};"}));
  const page = await context.newPage();
  const errors = []; page.on("pageerror", e => errors.push(e.message));
  // Upgrade a v1 database containing another subject's records; do not erase or mix them.
  await page.goto(`${base}missing`);
  await page.evaluate(async () => {
    const db = await new Promise((resolve,reject) => {
      const r = indexedDB.open("lockstep-vault",1);
      r.onupgradeneeded = () => { for (const [name,keyPath] of [["keys","id"],["entries","storageId"],["outbox","mutationId"]]) r.result.createObjectStore(name,{keyPath}); };
      r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error);
    });
    const tx = db.transaction(["keys","entries","outbox"],"readwrite");
    tx.objectStore("keys").put({id:"other:sentinel",subject:"other",sentinel:true});
    tx.objectStore("entries").put({storageId:"other:sentinel",id:"sentinel",subject:"other"});
    tx.objectStore("outbox").put({mutationId:"sentinel",subject:"other",entryId:"sentinel"});
    await new Promise(resolve => tx.oncomplete = resolve); db.close();
  });
  await page.goto(base); await page.waitForTimeout(1000);
  await page.evaluate(t => onGoogleCredential({credential:t}), token());
  await page.waitForSelector("#lock-dialog[open]");
  await page.fill("#lock-passcode",PASS); await page.fill("#lock-confirm",PASS);
  await page.click("#lock-form button[type=submit]");
  await page.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await page.evaluate(async () => { await addOtpUri("otpauth://totp/Test:u@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Test"); await loadEntries(true); });
  await page.waitForSelector("#entries .entry:not(.entry-skel)");
  await require("./render-performance")(page,"web");
  await require("./render-performance").verifyLongConfirmation(page,"web");
  const id = await page.$eval("#entries .entry:not(.entry-skel)",n=>n.dataset.id);
  const original = await page.evaluate(async id => (await LockstepVault.localEncryptedEntries("user-1")).find(e=>e.id===id),id);
  const begin = async pass => {
    if (!await page.evaluate(()=>state.editing)) await page.click("#edit-accounts");
    await page.locator(`#entries .entry[data-id="${id}"] [data-action=delete]`).click();
    await page.waitForSelector("#confirm-dialog[open]");
    await page.fill("#confirm-passkey",pass);
  };
  await begin(PASS); await page.click("#confirm-cancel");
  assert.equal((await control()).entries.length,1);
  assert.equal(await page.inputValue("#confirm-passkey"),"");
  await begin("wrong-passphrase"); await page.click("#confirm-accept");
  await page.waitForFunction(() => document.getElementById("toast").textContent.includes("Incorrect passphrase"));
  assert.equal((await control()).entries.length,1);
  // Cancel Google's confirmation: both copies stay intact.
  await page.evaluate(t => { state.token=t; }, token(600));
  await begin(PASS); await page.click("#confirm-accept");
  await page.waitForSelector("#reauth-dialog[open]");
  await page.evaluate(() => { document.getElementById("reauth-dialog").close(); });
  await page.waitForTimeout(150);
  assert.equal((await control()).entries.length,1);
  await page.evaluate(t => { state.token=t; }, token());
  // Fail the DELETE itself, after passphrase verification; the local copy is still visible.
  await page.route(`${API}/api/v1/entries/${id}`, r => r.request().method()==="DELETE" ? r.fulfill({status:503,contentType:"application/json",body:'{"error":"Deletion temporarily unavailable"}'}) : r.continue());
  await begin(PASS); await page.click("#confirm-accept");
  await page.waitForFunction(() => document.getElementById("toast").textContent.includes("Deletion temporarily unavailable"));
  assert.equal((await control()).entries.length,1);
  assert.equal(await page.locator("#entries .entry:not(.entry-skel)").count(),1);
  await page.unroute(`${API}/api/v1/entries/${id}`);
  await begin(PASS); await page.click("#confirm-accept");
  await page.waitForFunction(() => document.querySelectorAll("#entries .entry:not(.entry-skel)").length===0);
  assert.equal((await control()).entries.length,0);
  assert.equal(await page.evaluate(() => LockstepVault.pendingCount("user-1")),0);
  const replay = await page.evaluate(async ({id,payload}) => {
    try { await api(`/api/v1/entries/${id}`,{method:"PUT",body:JSON.stringify(payload)}); return "accepted"; } catch(e) { return e.code; }
  },{id,payload:original});
  assert.equal(replay,"DELETED");
  const migrated = await page.evaluate(async () => {
    const db = await new Promise(resolve => { const r=indexedDB.open("lockstep-vault"); r.onsuccess=()=>resolve(r.result); });
    const tx=db.transaction(["keys","entries","outbox"]);
    const result={version:db.version};
    for(const name of ["keys","entries","outbox"]) result[name]=await new Promise(resolve=>{const r=tx.objectStore(name).index("bySubject").getAll("other");r.onsuccess=()=>resolve(r.result.length);});
    db.close(); return result;
  });
  assert.deepEqual(migrated,{version:3,keys:1,entries:1,outbox:1});
  assert.deepEqual(errors,[]);
  console.log(`[${label}] cancellation, wrong passphrase, Google cancellation, failed request, deletion replay and v1 migration passed`);
  await browser.close();
})().catch(e => {console.error(`[${label}] FAILED`,e);process.exit(1);});
