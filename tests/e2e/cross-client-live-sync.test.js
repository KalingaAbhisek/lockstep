const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
const P = "live-sync-passphrase", owner = "user-1";
const push = process.env.LIVE_CHANGES === "1";
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = `${b64({alg:"RS256"})}.${b64({sub:owner,name:"Live Sync",email:"sync@example.test",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const uri = name => `otpauth://totp/${name}:account?secret=JBSWY3DPEHPK3PXP&issuer=${name}`;
const log = (...values) => console.log(`[${label}]`, ...values);
(async()=>{
 await fetch(`${API}/__control?reset=1`);
 const context=await chromium.launchPersistentContext(path.join(os.tmpdir(),`lockstep-live-sync-${Date.now()}`),{
  channel:"chromium",headless:true,acceptDownloads:true,ignoreDefaultArgs:["--disable-extensions"],
  args:["--headless=new",`--disable-extensions-except=${extensionDir}`,`--load-extension=${extensionDir}`]});
 try {
  // Exercise the actual 30-second timer callbacks, accelerated only in this fixture.
  await context.addInitScript(push=>{
   const interval=window.setInterval.bind(window);
   window.setInterval=(fn,ms,...args)=>ms===30000&&push?0:interval(fn,ms===30000?1000:ms,...args);
   if(push){
    const windowListener=window.addEventListener.bind(window),documentListener=document.addEventListener.bind(document);
    window.addEventListener=(name,...args)=>{if(name!=="focus")windowListener(name,...args)};
    document.addEventListener=(name,...args)=>{if(name!=="visibilitychange")documentListener(name,...args)};
   }
  },push);
  await context.route("https://accounts.google.com/**",r=>r.fulfill({contentType:"application/javascript",body:"window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};"}));
  let [worker]=context.serviceWorkers();if(!worker)worker=await context.waitForEvent("serviceworker");
  const extensionId=worker.url().split("/")[2];
  const web=await context.newPage(),errors=[];web.on("pageerror",e=>errors.push(e.message));
  await web.goto(WEB);await web.waitForTimeout(600);
  await web.evaluate(t=>onGoogleCredential({credential:t}),token);
  await web.waitForSelector("#lock-dialog[open]");
  await web.fill("#lock-passcode",P);await web.fill("#lock-confirm",P);await web.click('#lock-form button[type="submit"]');
  await web.waitForFunction(()=>!document.getElementById("lock-dialog").open);
  await web.evaluate(u=>importUris([u]),uri("Initial"));
  await worker.evaluate(async({token,P})=>{
   await chrome.storage.local.set({vaultSubject:"user-1",vaultDisplayName:"Live Sync",appSessionId:"session-token",appSessionExpiry:Date.now()+864e5});
   await chrome.storage.session.set({idToken:token,tokenExpiry:Date.now()+3600e3,interactiveSignInAt:Date.now()});
   await getLockConfig();await verifyLock(P);await synchronize();
  },{token,P});
  const popup=await context.newPage();popup.on("pageerror",e=>errors.push(e.message));
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  await popup.waitForSelector("#entries .entry:not(.entry-skel)");
  // Time from the change being stored on the server to the other client showing it (includes the mock API's 200 ms latency per request).
  const latencies=[];
  const expectName=async(page,name,present=true)=>{const started=Date.now();await page.waitForFunction(({name,present})=>[...document.querySelectorAll("#entries .issuer")].some(n=>n.textContent===name)===present,{name,present},{timeout:push?3000:15000});latencies.push(Date.now()-started);};
  if(push){
   const started=Date.now();
   while((await fetch(`${API}/__control`).then(r=>r.json())).liveConnections<2){if(Date.now()-started>10000)throw Error("Live channels did not connect");await web.waitForTimeout(100);}
   log("both live channels connected; timer, focus and visibility refreshes disabled");
  }
  await web.bringToFront();
  await worker.evaluate(u=>addOtpUri(u),uri("From extension"));
  await expectName(web,"From extension");
  await web.evaluate(u=>importUris([u]),uri("From web"));
  await popup.bringToFront();await expectName(popup,"From web");
  log("additions detected automatically in both directions");
  await worker.evaluate(async()=>{const entry=(await localEntries()).find(e=>e.issuer==="From extension");await updateEntry(entry.id,"Renamed extension",entry.accountName);});
  await web.bringToFront();await expectName(web,"Renamed extension");
  await web.evaluate(async()=>{const entry=(await LockstepVault.listEntries("user-1")).find(e=>e.issuer==="From web");await LockstepVault.updateEntry("user-1",entry.id,"Renamed web",entry.accountName);await syncVault();});
  await popup.bringToFront();await expectName(popup,"Renamed web");
  log("edits detected automatically in both directions");
  await worker.evaluate(async P=>{const entry=(await localEntries()).find(e=>e.issuer==="Renamed extension");await deleteEntry(entry.id,P);},P);
  await web.bringToFront();await expectName(web,"Renamed extension",false);
  await web.evaluate(async()=>{const entry=(await LockstepVault.listEntries("user-1")).find(e=>e.issuer==="Renamed web");await api(`/api/v1/entries/${entry.id}`,{method:"DELETE"});await LockstepVault.acceptServerDeletion("user-1",entry.id);});
  await popup.bringToFront();await expectName(popup,"Renamed web",false);
  log("deletions detected automatically in both directions");
  if(push)log(`shown on the other client after (ms): ${latencies.join(", ")}`);
  if(push){
   const changed="changed-live-passphrase";
   await web.bringToFront();await web.click("#open-settings");await web.click("#settings-lock");
   await web.fill("#lock-passcode",changed);await web.fill("#lock-confirm",changed);
   await web.click('#lock-form button[type="submit"]');await web.waitForFunction(()=>!document.getElementById("lock-dialog").open);
   await popup.waitForSelector("#locked:not(.hidden)",{timeout:3000});
   await popup.fill("#unlock-passcode",changed);await popup.click('#unlock-form button[type="submit"]');await expectName(popup,"Initial");
   await worker.evaluate(P=>setLockConfig(P,300,false,false),P);
   await web.waitForSelector("#locked:not(.hidden)",{timeout:3000});
   await web.fill("#unlock-passcode",P);await web.click('#unlock-form button[type="submit"]');await expectName(web,"Initial");
   log("passphrase changes locked the opposite client immediately in both directions; new-passphrase unlock succeeded");
  }
  await web.evaluate(async()=>{const lock=await api("/api/v1/lock");await api("/api/v1/lock",{method:"PUT",body:JSON.stringify({...lock,timeoutSeconds:600,expectedRevision:lock.vaultRevision})});});
  await popup.waitForFunction(()=>lockConfig.timeoutSeconds===600,null,{timeout:15000});
  await worker.evaluate(async()=>{const lock=await api("/api/v1/lock");await api("/api/v1/lock",{method:"PUT",body:JSON.stringify({...lock,timeoutSeconds:900,expectedRevision:lock.vaultRevision})});});
  await web.bringToFront();await web.waitForFunction(()=>state.lockConfig.timeoutSeconds===900,null,{timeout:15000});
  log("shared lock settings detected automatically in both directions");
  await web.click("#open-add");await web.click("#open-manual");
  await web.fill("#manual-issuer","Unsaved web draft");
  await web.waitForTimeout(2200);
  assert.equal(await web.inputValue("#manual-issuer"),"Unsaved web draft","routine refresh must preserve an open draft");
  if(push){
   // A change that arrives while a dialog is open keeps the draft, and shows the moment the dialog closes.
   await worker.evaluate(u=>addOtpUri(u),uri("While web dialog open"));
   await web.waitForTimeout(1500);
   assert.equal(await web.inputValue("#manual-issuer"),"Unsaved web draft","a live change must not disturb an open draft");
   await web.click('#manual-dialog [data-close="manual-dialog"]');
   await expectName(web,"While web dialog open");
   await popup.click("#entries .entry [data-action=qr]");await popup.waitForSelector("#qr-dialog[open]");
   await web.evaluate(u=>importUris([u]),uri("While popup dialog open"));
   await popup.waitForTimeout(1500);
   await popup.click("#close-qr");
   await expectName(popup,"While popup dialog open");
   log("changes received during an open dialog appeared as soon as it closed, in both clients");
   await web.click("#open-add");await web.click("#open-manual");await web.fill("#manual-issuer","Unsaved web draft");
  }
  await worker.evaluate(P=>rotateEncryptionKey(P),P);
  await web.waitForSelector("#locked:not(.hidden)",{timeout:push?3000:15000});
  assert.equal(await web.evaluate(()=>state.lockConfig.wrappedKey.currentVersion),2);
  assert.equal(await web.evaluate(()=>LockstepVault.isUnlocked("user-1")),false,"remote rotation must clear the webapp's unlocked key");
  assert.equal(await web.evaluate(()=>sessionStorage.getItem(sessionKeyStorageKey())),null,"remote rotation must remove the webapp's saved unlocked session");
  if(push)await web.waitForFunction(async()=>{
   const rows=await LockstepVault.localEncryptedEntries("user-1");return rows.length>0&&rows.every(row=>row.keyVersion===2);
  },null,{timeout:3000});
  await web.fill("#unlock-passcode",P);await web.click('#unlock-form button[type="submit"]');await expectName(web,"Initial");
  log("extension rotation detected; web unlock succeeded without reloading");
  await popup.bringToFront();await popup.click("#edit");await popup.click("#add");await popup.click("#method-manual");
  await popup.fill("#manual-issuer","Unsaved extension draft");
  await popup.waitForTimeout(2200);
  assert.equal(await popup.inputValue("#manual-issuer"),"Unsaved extension draft","routine refresh must preserve an open draft");
  await web.bringToFront();
  await web.click("#open-settings");await web.click("#settings-key-rotate");
  await web.waitForSelector("#confirm-dialog[open]");await web.fill("#confirm-passkey",P);await web.click("#confirm-accept");
  await web.waitForFunction(()=>/rotated to version 3/.test(document.getElementById("toast").textContent),null,{timeout:30000});
  await popup.bringToFront();await popup.waitForSelector("#locked:not(.hidden)",{timeout:push?3000:15000});
  assert.equal(await worker.evaluate(()=>LockstepVault.isUnlocked("user-1")),false,"remote rotation must clear the extension's unlocked key");
  assert.equal(await worker.evaluate(async()=>Boolean((await chrome.storage.session.get("unlockedMaster")).unlockedMaster)),false,"remote rotation must remove the extension's saved unlocked session");
  if(push)await worker.evaluate(async()=>{
   const start=Date.now();
   while(!(await LockstepVault.localEncryptedEntries("user-1")).every(row=>row.keyVersion===3)){
    if(Date.now()-start>3000)throw Error("Locked extension did not receive the new ciphertext");
    await new Promise(resolve=>setTimeout(resolve,30));
   }
  });
  await popup.fill("#unlock-passcode",P);await popup.click('#unlock-form button[type="submit"]');await expectName(popup,"Initial");
  log("web rotation detected; extension unlock succeeded without reloading");
  if(push){
   await fetch(`${API}/__control?closeStreams=1`);
   await web.evaluate(u=>importUris([u]),uri("After stream reconnect"));
   await expectName(popup,"After stream reconnect");
   log("changes during a disconnected channel caught up automatically");
   const initiator=label.includes("cookie")?popup:web;
   await initiator.bringToFront();await initiator.click(initiator===web?"#open-settings":"#settings");
   await initiator.click("#settings-signout-all");await initiator.waitForSelector("#confirm-dialog[open]");await initiator.click("#confirm-accept");
   await web.waitForSelector("#signed-out:not(.hidden)",{timeout:3000});await popup.waitForSelector("#signed-out:not(.hidden)",{timeout:3000});
   assert.equal(await web.evaluate(()=>LockstepVault.isUnlocked("user-1")),false);
   assert.equal(await worker.evaluate(()=>LockstepVault.isUnlocked("user-1")),false);
   assert((await fetch(`${API}/__control`).then(r=>r.json())).entries.length>0,"sign-out everywhere removed vault data");
   log("session-ending notification signs out the other client before the initiating HTTP acknowledgement");
  }
  assert.deepEqual(errors,[]);
 } finally {await context.close();}
})().catch(error=>{console.error(`[${label}] FAILED`,error);process.exitCode=1;});
