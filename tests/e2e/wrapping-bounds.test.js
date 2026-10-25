const {chromium}=require("playwright"),path=require("node:path"),assert=require("node:assert/strict");
(async()=>{const browser=await chromium.launch();try{for(const client of ["webapp","extension"]){
 const page=await browser.newPage();await page.route("http://localhost/**",r=>r.fulfill({contentType:"text/html",body:"<!doctype html>"}));await page.goto("http://localhost/");
 await page.addScriptTag({path:path.join(__dirname,"../..",client,"crypto-store.js")});
 const result=await page.evaluate(async()=>{
  const V=LockstepVault,owner="wrapping-bounds",pass="wrapping-test-passphrase";await V.configurePassphrase(owner,pass);
  const db=await new Promise((resolve,reject)=>{const r=indexedDB.open("lockstep-vault");r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);});
  const original=await new Promise(resolve=>{const r=db.transaction("keys").objectStore("keys").get(owner+":master");r.onsuccess=()=>resolve(r.result);});
  const store=record=>new Promise((resolve,reject)=>{const t=db.transaction("keys","readwrite");t.objectStore("keys").put(record);t.oncomplete=resolve;t.onabort=()=>reject(t.error);});
  const results=[];
  for(const invalid of [{iterations:1e12},{wrapping:"ARGON2ID-V13/AES-256-GCM",iterations:3,memoryKiB:2**31,parallelism:1},{wrapping:"UNKNOWN"},{salt:btoa("s".repeat(64))}]){
   V.lock(owner);await store({...original,...invalid});let expensive=0,accepted=false;
   const derive=crypto.subtle.deriveKey.bind(crypto.subtle),argon=globalThis.LockstepArgon2id;
   crypto.subtle.deriveKey=async()=>{expensive++;throw Error("derivation must not start");};
   globalThis.LockstepArgon2id={hash:async()=>{expensive++;throw Error("hash must not start");}};
   try{await V.unlock(owner,pass);accepted=true;}catch{}finally{crypto.subtle.deriveKey=derive;globalThis.LockstepArgon2id=argon;}
   results.push({expensive,accepted,unlocked:V.isUnlocked(owner)});
  }
  await store(original);await V.unlock(owner,pass);db.close();return {results,valid:V.isUnlocked(owner)};
 });
 assert(result.valid,client+" valid vault no longer unlocks");
 for(const row of result.results){assert.equal(row.expensive,0,client+" corrupt wrapping metadata reached an unbounded KDF");assert.equal(row.accepted,false);assert.equal(row.unlocked,false);}
 await page.close();console.log(client+": invalid wrapping metadata rejected before KDF; valid vault still unlocks");
}}finally{await browser.close();}})().catch(error=>{console.error(error);process.exitCode=1;});
