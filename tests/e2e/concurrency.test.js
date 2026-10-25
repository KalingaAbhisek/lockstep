const fs=require("node:fs"),path=require("node:path"),assert=require("node:assert/strict");
const {chromium}=require("playwright");
const root=path.resolve(__dirname,"../..");
const PASS="concurrency-test-passphrase", SUBJECT="concurrency-owner";

(async()=>{
 const browser=await chromium.launch();
 try { for(const client of ["webapp","extension"]){
  const context=await browser.newContext();
  await context.route("http://localhost/**",r=>r.fulfill({contentType:r.request().url().endsWith(".js")?"application/javascript":"text/html",body:r.request().url().endsWith(".js")?fs.readFileSync(path.join(root,client,"crypto-store.js")):"<!doctype html><script src='/crypto-store.js'></script>"}));
  const a=await context.newPage();await a.goto("http://localhost/");
  await a.evaluate(async({s,p})=>{
   const V=LockstepVault;V.setLabelEncryption(true);await V.configurePassphrase(s,p);await V.markWrappedKeySynced(s, 1, await V.exportWrappedKey(s));
   const entry=await V.addOtpUri(s,"otpauth://totp/Original:user?secret=JBSWY3DPEHPK3PXP&issuer=Original");window.entryId=entry.id;
   window.remote=null;window.transport={put:async(id,payload)=>{
    if(remote&&remote.mutationId!==payload.mutationId&&remote.mutationId!==payload.baseMutationId)throw Object.assign(new Error("Conflict"),{status:400,code:"CONFLICT"});
    window.remote={...payload,id};
   },list:async()=>remote?[remote]:[]};
   await V.flushOutbox(s,transport);
  },{s:SUBJECT,p:PASS});
  const b=await context.newPage();await b.goto("http://localhost/");
  await b.evaluate(async({s,p})=>{LockstepVault.setLabelEncryption(true);await LockstepVault.unlock(s,p)},{s:SUBJECT,p:PASS});

  // A rejected response must leave all existing rows intact, even after writes were queued.
  for(const cloneFailure of [false,true]){
   await assert.rejects(a.evaluate(async({s,cloneFailure})=>{
    const invalid=cloneFailure?{...remote,id:crypto.randomUUID(),uncloneable:()=>{}}:{id:"invalid-id"};
    await LockstepVault.synchronize(s,{list:async()=>[invalid]});
   },{s:SUBJECT,cloneFailure}));
   assert.equal(await a.evaluate(s=>LockstepVault.localEncryptedEntries(s).then(e=>e.length),SUBJECT),1);
  }

  // A's delayed acknowledgement must not clear B's newer pending passphrase change.
  const ackSubject=SUBJECT+"-ack";
  const submitted=await a.evaluate(async({s,p})=>{await LockstepVault.configurePassphrase(s,p);return LockstepVault.exportWrappedKey(s)},{s:ackSubject,p:PASS});
  await b.evaluate(async({s,p})=>{await LockstepVault.unlock(s,p);await LockstepVault.configurePassphrase(s,p+"-new")},{s:ackSubject,p:PASS});
  assert.equal(await a.evaluate(({s,key})=>LockstepVault.markWrappedKeySynced(s,2,key),{s:ackSubject,key:submitted}),false);
  assert.ok(await b.evaluate(s=>LockstepVault.pendingWrappedKeyUpload(s),ackSubject));
  const current=await b.evaluate(s=>LockstepVault.exportWrappedKey(s),ackSubject);
  assert.equal(await a.evaluate(({s,key})=>LockstepVault.markWrappedKeySynced(s,3,key),{s:ackSubject,key:current}),true);
  assert.equal(await a.evaluate(({s,key})=>LockstepVault.markWrappedKeySynced(s,2,key),{s:ackSubject,key:current}),false);

  // A response captured before deletion cannot restore a ghost card, including across tabs.
  await a.evaluate(s=>{window.oldSnapshot=[remote];window.pull=LockstepVault.synchronize(s,{...transport,list:async()=>{window.reached=true;await new Promise(r=>window.release=r);return oldSnapshot;}})},SUBJECT);
  await a.waitForFunction(()=>window.reached);
  await b.evaluate(async s=>{await LockstepVault.acceptServerDeletion(s,(await LockstepVault.localEncryptedEntries(s))[0].id)},SUBJECT);
  await a.evaluate(async()=>{remote=null;release();await pull});
  assert.equal(await a.evaluate(s=>LockstepVault.listEntries(s).then(e=>e.length),SUBJECT),0);

  // Recreate a fixture, then ensure edits upload in dependency order despite a backwards clock.
  await a.evaluate(async s=>{
   const V=LockstepVault;entryId=(await V.addOtpUri(s,"otpauth://totp/Original:user?secret=JBSWY3DPEHPK3PXP&issuer=Original")).id;await V.flushOutbox(s,transport);
   const now=Date.now;try{Date.now=()=>now()+10000;await V.updateEntry(s,entryId,"Earlier","user");Date.now=now;await V.updateEntry(s,entryId,"Latest","user");}finally{Date.now=now}
   // Exercise the upgrade path too: old outbox records have no sequence field.
   const db=await new Promise(resolve=>{const r=indexedDB.open("lockstep-vault");r.onsuccess=()=>resolve(r.result)});
   const tx=db.transaction("outbox","readwrite"),store=tx.objectStore("outbox");
   const rows=await new Promise(resolve=>{const r=store.getAll();r.onsuccess=()=>resolve(r.result)});
   for(const row of rows){delete row.sequence;store.put(row)}await new Promise(resolve=>tx.oncomplete=resolve);db.close();
   await V.synchronize(s,transport);
  },SUBJECT);
  assert.equal(await a.evaluate(s=>LockstepVault.listEntries(s).then(e=>e[0].issuer),SUBJECT),"Latest");

  // Hold rotation across the network window. A second tab must refuse edits before accepting a secret.
  await a.evaluate(async({s,p})=>{window.prepared=await LockstepVault.prepareMasterRotation(s,p)},{s:SUBJECT,p:PASS});
  const blocked=await b.evaluate(async s=>{try{await LockstepVault.addOtpUri(s,"otpauth://totp/During:user?secret=GEZDGNBVGY3TQOJQ&issuer=During");return "accepted"}catch(e){return e.code}},SUBJECT);
  assert.equal(blocked,"ROTATION_IN_PROGRESS");
  await a.evaluate(async s=>{remote=prepared.entries[0];await LockstepVault.commitMasterRotation(prepared,prepared.entries,2)},SUBJECT);
  const stale=await b.evaluate(async s=>{try{await LockstepVault.addOtpUri(s,"otpauth://totp/Stale:user?secret=GEZDGNBVGY3TQOJQ&issuer=Stale");return "accepted"}catch(e){return e.code}},SUBJECT);
  assert.equal(stale,"VAULT_LOCKED");
  await b.evaluate(async({s,p})=>{await LockstepVault.unlock(s,p);await LockstepVault.addOtpUri(s,"otpauth://totp/After:user?secret=GEZDGNBVGY3TQOJQ&issuer=After")},{s:SUBJECT,p:PASS});
  assert.equal(await b.evaluate(s=>LockstepVault.listEntries(s).then(e=>e.filter(x=>x.error).length),SUBJECT),0);
  assert.equal(await a.evaluate(s=>LockstepVault.pendingCount(s),SUBJECT),1);

  // A new sequence remains monotonic after removing legacy rows and a clock adjustment.
  const sequences=await b.evaluate(async s=>{
   const db=await new Promise(resolve=>{const r=indexedDB.open("lockstep-vault");r.onsuccess=()=>resolve(r.result)});
   const tx=db.transaction("outbox");const rows=await new Promise(resolve=>{const r=tx.objectStore("outbox").getAll();r.onsuccess=()=>resolve(r.result)});db.close();return rows.filter(r=>r.subject===s).map(r=>r.sequence);
  },SUBJECT);
  assert.ok(sequences.every(Number.isSafeInteger));
  await b.evaluate(async s=>{
   await Promise.all(["One","Two"].map(label=>LockstepVault.addOtpUri(s,`otpauth://totp/${label}:user?secret=JBSWY3DPEHPK3PXP&issuer=${label}`)));
  },SUBJECT);
  assert.equal(await b.evaluate(s=>LockstepVault.pendingCount(s),SUBJECT),3);

  // An explicit lock must win over recovery-key import paused inside key derivation.
  await a.evaluate(async({s,p})=>{
   const V=LockstepVault;await V.configurePassphrase(s,p);await V.addOtpUri(s,"otpauth://totp/Recovery:user?secret=JBSWY3DPEHPK3PXP&issuer=Recovery");
   window.beforeRecovery=await V.exportWrappedKey(s);const recovery=await V.exportRecoveryKey(s);
   const original=crypto.subtle.deriveKey.bind(crypto.subtle);window.recoveryReached=false;
   crypto.subtle.deriveKey=async(...args)=>{if(args[0].name==="PBKDF2"){window.recoveryReached=true;await new Promise(r=>window.releaseRecovery=r)}return original(...args)};
   window.recovering=V.importRecoveryKey(s,recovery,p+"-new").then(()=>"accepted",e=>e.code).finally(()=>crypto.subtle.deriveKey=original);
  },{s:SUBJECT+"-recovery",p:PASS});
  await a.waitForFunction(()=>window.recoveryReached);
  const locked=await a.evaluate(async s=>{LockstepVault.lock(s);releaseRecovery();return {outcome:await recovering,unlocked:LockstepVault.isUnlocked(s),sameKey:(await LockstepVault.exportWrappedKey(s)).wrappedMasterKey===beforeRecovery.wrappedMasterKey}},SUBJECT+"-recovery");
  assert.deepEqual(locked,{outcome:"VAULT_LOCKED",unlocked:false,sameKey:true});

  // Without Web Locks, retain the old wrapper so an intervening offline create remains recoverable.
  for(const page of [a,b])await page.evaluate(()=>Object.defineProperty(navigator,"locks",{value:undefined,configurable:true}));
  const fallbackSubject=SUBJECT+"-fallback";
  await a.evaluate(async({s,p})=>{
   remote=null;await LockstepVault.configurePassphrase(s,p);await LockstepVault.markWrappedKeySynced(s, 1, await LockstepVault.exportWrappedKey(s));
   await LockstepVault.addOtpUri(s,"otpauth://totp/Before:user?secret=JBSWY3DPEHPK3PXP&issuer=Before");
   await LockstepVault.flushOutbox(s,transport);
  },{s:fallbackSubject,p:PASS});
  await b.evaluate(async({s,p})=>LockstepVault.unlock(s,p),{s:fallbackSubject,p:PASS});
  await a.evaluate(async({s,p})=>{window.prepared=await LockstepVault.prepareMasterRotation(s,p)},{s:fallbackSubject,p:PASS});
  await b.evaluate(s=>LockstepVault.addOtpUri(s,"otpauth://totp/Intervening:user?secret=GEZDGNBVGY3TQOJQ&issuer=Intervening"),fallbackSubject);
  const recovered=await a.evaluate(async({s,p})=>{
   await LockstepVault.commitMasterRotation(prepared,prepared.entries,2);LockstepVault.lock(s);await LockstepVault.unlock(s,p);
   const rescued=await LockstepVault.rescueStrandedEntries(s,p);
   return {rescued,entries:await LockstepVault.listEntries(s)};
  },{s:fallbackSubject,p:PASS});
  assert.equal(recovered.rescued,1);
  assert.equal(recovered.entries.length,2);
  assert.ok(recovered.entries.every(e=>!e.error));
  // A valid recovery key still restores when the first twenty accounts are damaged.
  const damagedSubject=SUBJECT+"-damaged";
  const restored=await a.evaluate(async({s,p})=>{
   const V=LockstepVault;await V.configurePassphrase(s,p);
   for(let i=0;i<21;i++)await V.addOtpUri(s,`otpauth://totp/Recovery:user${i}?secret=JBSWY3DPEHPK3PXP&issuer=Recovery`);
   const key=await V.exportRecoveryKey(s),rows=await V.localEncryptedEntries(s);
   await new Promise((resolve,reject)=>{const req=indexedDB.open("lockstep-vault");req.onsuccess=()=>{const db=req.result,t=db.transaction("entries","readwrite");for(const row of rows.slice(0,20))t.objectStore("entries").put({...row,encryptedSecret:btoa("damaged cipher".repeat(3))});t.oncomplete=()=>{db.close();resolve()};t.onerror=()=>reject(t.error)};req.onerror=()=>reject(req.error)});
   V.lock(s);await V.importRecoveryKey(s,key,p);
   return {unlocked:V.isUnlocked(s),healthy:(await V.listEntries(s)).filter(e=>!e.error).length};
  },{s:damagedSubject,p:PASS});
  assert.equal(restored.unlocked,true);assert.equal(restored.healthy,1);
  // No notification is delivered to this tab: the persisted key boundary alone must reject stale writes.
  const erasedSubject=SUBJECT+"-erased";
  await a.evaluate(async({s,p})=>LockstepVault.configurePassphrase(s,p),{s:erasedSubject,p:PASS});
  await b.evaluate(async({s,p})=>LockstepVault.unlock(s,p),{s:erasedSubject,p:PASS});
  await a.evaluate(s=>LockstepVault.clearSubject(s),erasedSubject);
  await assert.rejects(b.evaluate(s=>LockstepVault.addOtpUri(s,"otpauth://totp/Stale:user?secret=JBSWY3DPEHPK3PXP&issuer=Stale"),erasedSubject),/removed|changed/);
  assert.equal(await b.evaluate(s=>LockstepVault.isUnlocked(s),erasedSubject),false);
  assert.equal(await a.evaluate(s=>LockstepVault.localEncryptedEntries(s).then(e=>e.length),erasedSubject),0);
  await context.close();
  console.log(`${client}: cross-tab rotation, stale replies, legacy queue ordering and persistent sequences passed`);
 }}finally{await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
