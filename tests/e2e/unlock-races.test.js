const {chromium}=require("playwright"),fs=require("fs"),path=require("path"),assert=require("node:assert/strict");
(async()=>{const browser=await chromium.launch();try{for(const client of ["webapp","extension"]){
 const context=await browser.newContext();await context.route("http://localhost/**",r=>r.fulfill({contentType:r.request().url().endsWith(".js")?"application/javascript":"text/html",body:r.request().url().endsWith(".js")?fs.readFileSync(path.join(__dirname,"../..",client,"crypto-store.js")):"<!doctype html><script src='/crypto-store.js'></script>"}));
 const a=await context.newPage(),b=await context.newPage();await a.goto("http://localhost/");await b.goto("http://localhost/");
 for(const mode of ["unlock","restore","unlock-aba","restore-aba","unlock-legacy"]){const subject="race-"+mode,pass="race-test-passphrase";
 const setup=await a.evaluate(async({s,p,mode})=>{if(mode==="unlock-legacy"){await new Promise((resolve,reject)=>{const request=indexedDB.open("lockstep-vault");request.onsuccess=()=>{const db=request.result,t=db.transaction("keys","readwrite");t.objectStore("keys").put({id:s+":master",subject:s,raw:btoa("m".repeat(32)),currentVersion:1,createdAt:Date.now()});t.oncomplete=()=>{db.close();resolve()};t.onerror=()=>reject(t.error)}});return {snapshot:null,key:null};}await LockstepVault.configurePassphrase(s,p);return {snapshot:await LockstepVault.exportSessionKey(s,"tab"),key:await LockstepVault.exportWrappedKey(s)}},{s:subject,p:pass,mode});
 await b.evaluate(({s,p,mode,snapshot})=>{
  window.reached=false;let release;window.releaseCrypto=()=>release();const barrier=new Promise(r=>release=r);
  const name=mode.startsWith("unlock")?"deriveKey":"decrypt",original=crypto.subtle[name].bind(crypto.subtle);
  crypto.subtle[name]=async(...args)=>{window.reached=true;await barrier;return original(...args)};
  window.pending=(mode.startsWith("unlock")?LockstepVault.unlock(s,p):LockstepVault.restoreSessionKey(s,snapshot,"tab")).then(()=>"accepted",e=>e.code).finally(()=>crypto.subtle[name]=original);
 },{s:subject,p:pass,mode,snapshot:setup.snapshot});
 await b.waitForFunction(()=>window.reached);await a.evaluate(s=>LockstepVault.clearSubject(s),subject);
 if(mode.endsWith("-aba"))await a.evaluate(({s,key})=>LockstepVault.synchronizeWrappedKey(s,key,1),{s:subject,key:setup.key});
 await b.evaluate(()=>releaseCrypto());
 const outcome=await b.evaluate(()=>pending);assert.equal(outcome,"VAULT_LOCKED",client+" "+mode+" completed after erasure");assert.equal(await b.evaluate(s=>LockstepVault.isUnlocked(s),subject),false);
 }
 const exports=await a.evaluate(async()=>{
  const V=LockstepVault,s="concurrent-session-export",p="session-export-passphrase";await V.configurePassphrase(s,p);
  const original=crypto.subtle.generateKey.bind(crypto.subtle);crypto.subtle.generateKey=async(...args)=>{await new Promise(r=>setTimeout(r,10));return original(...args)};
  let snapshots;try{snapshots=await Promise.all([V.exportSessionKey(s,"same-tab"),V.exportSessionKey(s,"same-tab")]);}finally{crypto.subtle.generateKey=original;}
  const resumed=[];for(const snapshot of snapshots){V.lock(s);resumed.push(await V.restoreSessionKey(s,snapshot,"same-tab"));}return resumed;
 });assert.deepEqual(exports,[true,true],client+" concurrent exports produced an unusable snapshot");
 const reads=await a.evaluate(async()=>{
  const V=LockstepVault,s="read-during-relock",p="read-race-passphrase";
  await V.configurePassphrase(s,p);V.setLabelEncryption(false);
  const entry=await V.addOtpUri(s,"otpauth://totp/Race:user?secret=JBSWY3DPEHPK3PXP&issuer=Race");
  const outcomes=[];
  for(const action of [()=>V.listEntries(s),()=>V.otpAuthUri(s,entry.id),()=>V.exportText(s)]){
   let release,reached;const ready=new Promise(r=>reached=r),barrier=new Promise(r=>release=r);
   const original=crypto.subtle.decrypt.bind(crypto.subtle);
   crypto.subtle.decrypt=async(...args)=>{crypto.subtle.decrypt=original;reached();await barrier;return original(...args)};
   const reading=action().then(()=>"accepted",e=>e.code);
   await ready;V.lock(s);await V.unlock(s,p);release();outcomes.push(await reading);
  }
  const recovery=V.exportRecoveryKey(s).then(()=>"accepted",e=>e.code);V.lock(s);outcomes.push(await recovery);
  return outcomes;
 });assert.deepEqual(reads,["VAULT_LOCKED","VAULT_LOCKED","VAULT_LOCKED","VAULT_LOCKED"],client+" a stale read/export returned secrets after locking");
 await context.close();console.log(client+": unlock/resume/legacy erasure fences, concurrent session snapshots and stale read/export cancellation passed");
}}finally{await browser.close()}})().catch(e=>{console.error(e);process.exitCode=1});
