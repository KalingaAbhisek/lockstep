const fs=require("node:fs"),vm=require("node:vm"),assert=require("node:assert/strict"),path=require("node:path");
const worker=fs.readFileSync(path.resolve(__dirname,"../../extension/service-worker.js"),"utf8");
function between(start,end){return worker.slice(worker.indexOf(start),worker.indexOf(end,worker.indexOf(start)));}
(async()=>{
 for(const status of [200,401]){
  let local={vaultSubject:"owner",appSessionId:"old"},release;
  const sandbox={appSession:async()=>local.appSessionId,validStoredGoogleToken:async()=>"",subject:async()=>local.vaultSubject,
   AUTHSYNC_CONFIG:{apiBaseUrl:"https://example.invalid"},fetch:async()=>new Promise(resolve=>release=()=>resolve({ok:status===200,status,json:async()=>({code:"SESSION_REVOKED",error:"old session"})})),
   coded:(code,message)=>Object.assign(new Error(message),{code}),forgetRecentReads:()=>{},stopPendingSync:async()=>{},
   LockstepVault:{lock:()=>{}},chrome:{storage:{session:{clear:async()=>{}},local:{get:async()=>({...local}),remove:async keys=>{for(const key of keys)delete local[key]},set:async values=>Object.assign(local,values)}}}};
  sandbox.AbortSignal=AbortSignal;vm.createContext(sandbox);vm.runInContext(between("let authenticationGeneration","let tokenRefreshPromise")+
   between("async function invalidateAuthentication(","async function subject(")+between("const syncRetryStates", "async function startScan("),sandbox);
  const pending=sandbox.api("/audit").then(()=>"accepted",e=>e.code);
  while(!release)await new Promise(r=>setTimeout(r,0));
  vm.runInContext("authenticationGeneration++",sandbox);
  await sandbox.writeAuthentication(()=>sandbox.chrome.storage.local.set({appSessionId:"new"}));
  release();assert.equal(await pending,"SESSION_CHANGED");assert.equal(local.appSessionId,"new");
  release=null;
  assert.equal(await sandbox.api("/queued-old-session",{expectedAuthentication:{generation:-1,owner:"owner",session:"old"}}).catch(e=>e.code),"SESSION_CHANGED");
  assert.equal(release,null,"queued work sent a request under newer credentials");
  vm.runInContext("authenticationTransition=true",sandbox);
  assert.equal(await sandbox.api("/during-sign-in").catch(e=>e.code),"SESSION_CHANGED");
  assert.equal(release,null,"an incomplete sign-in sent mixed credentials");
 }
 {
  let local={vaultSubject:"owner",appSessionId:"old"},releaseSession;
  const sandbox={SESSION_REVOKED_NOTICE_KEY:"notice",token:async()=>"google",subject:async()=>local.vaultSubject,
   appSession:async()=>local.appSessionId,validStoredGoogleToken:async()=>"",AUTHSYNC_CONFIG:{apiBaseUrl:"https://example.invalid"},
   authorize:async()=>({sub:"owner",name:"Owner"}),forgetRecentReads:()=>{},stopPendingSync:async()=>{},
   coded:(code,message)=>Object.assign(new Error(message),{code}),
   LockstepVault:{keyState:async()=>"protected",lock:()=>{}},
   chrome:{storage:{session:{remove:async()=>{},set:async()=>{}},local:{get:async()=>({...local}),set:async values=>Object.assign(local,values),remove:async keys=>{for(const key of Array.isArray(keys)?keys:[keys])delete local[key]}}}},
   fetch:async url=>url.endsWith("/session")?new Promise(resolve=>releaseSession=()=>resolve({ok:true,status:200,json:async()=>({sessionToken:"new",expiresAtEpochMillis:Date.now()+3600000})})):{ok:true,status:200,json:async()=>({exists:true})}};
  sandbox.AbortSignal=AbortSignal;vm.createContext(sandbox);vm.runInContext(between("let authenticationGeneration","let tokenRefreshPromise")+
   between("async function login(","// Resetting the vault")+between("async function registerAppSession(","async function appSession(")+
   between("const syncRetryStates", "async function startScan("),sandbox);
  sandbox.backendAccountExists=async()=>Boolean((await sandbox.api("/account")).exists);
  sandbox.synchronize=async()=>assert.equal(vm.runInContext("authenticationTransition",sandbox),false);
  const signingIn=sandbox.login();while(!releaseSession)await new Promise(r=>setTimeout(r,0));
  assert.equal(await sandbox.api("/during-sign-in").catch(e=>e.code),"SESSION_CHANGED");
  releaseSession();assert.equal((await signingIn).newAccount,false);assert.equal(local.appSessionId,"new");
 }
 {
  let local={vaultSubject:"A",appSessionId:"a"},flags={},releaseKey,started;
  const reached=new Promise(r=>started=r);
  const box={SESSION_REVOKED_NOTICE_KEY:"notice",REPLACED_VAULT_KEY:"replaced",authorize:async()=>({sub:"A"}),
   registerAppSession:async()=>{},backendAccountExists:async()=>true,synchronize:async()=>{},
   coded:(code,message)=>Object.assign(new Error(message),{code}),LockstepVault:{keyState:async()=>{started();await new Promise(r=>releaseKey=r);return "none";}},
   chrome:{storage:{local:{get:async()=>({...local}),remove:async()=>{}},session:{set:async values=>Object.assign(flags,values),remove:async key=>delete flags[key]}}}};
  vm.createContext(box);vm.runInContext(between("let authenticationGeneration","let tokenRefreshPromise")+between("async function login(","// Resetting the vault"),box);
  const old=box.login().then(()=>"accepted",e=>e.code);await reached;
  vm.runInContext("authenticationGeneration++",box);
  const newer=box.writeAuthentication(async()=>{local={vaultSubject:"B",appSessionId:"b"};flags.restoreAuthorized=false;});
  releaseKey();assert.equal(await old,"SESSION_CHANGED");await newer;
  assert.equal(flags.restoreAuthorized,false);assert.equal(local.vaultSubject,"B");
 }
 console.log("Extension authentication: stale responses preserve new sessions; sign-in publishes complete credentials before API use");
})().catch(e=>{console.error(e);process.exit(1)});
