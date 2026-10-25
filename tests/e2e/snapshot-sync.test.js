const fs=require("node:fs"),path=require("node:path"),vm=require("node:vm"),assert=require("node:assert/strict");
function section(source,start,end){return source.slice(source.indexOf(start),source.indexOf(end,source.indexOf(start)));}
(async()=>{
 for(const ext of [false,true])for(const scenario of ["stable","rotated","switched","missing","stale"]){
  const source=fs.readFileSync(path.join(__dirname,"../..",ext?"extension/service-worker.js":"webapp/app.js"),"utf8");
  let generation=1,stored=0,locked=0,calls=[];
  const authentication={subject:"A",owner:"A",generation:1};
  const snapshot={exists:scenario!=="missing",lock:{enabled:true,timeoutSeconds:300,wrappedKey:{currentVersion:scenario==="rotated"?2:1},vaultRevision:2},entries:[{id:"snapshot-entry"}],cursor:40,full:false};
  const box={state:{bootstrapUnsupported:false,changesUnsupported:false},bootstrapUnsupported:false,changesUnsupported:false,
   authenticationGeneration:1,authenticationSnapshot:()=>ext?Promise.resolve(authentication):authentication,
   authenticationMatches:()=>ext?Promise.resolve(generation===1):generation===1,assertSyncCooldown(){},
   api:async(url,options)=>{assert.equal(options.expectedAuthentication,authentication);calls.push(url);return snapshot;},
   coded:(code,message)=>Object.assign(new Error(message),{code}),
   LockstepVault:{isUnlocked:()=>true,expectedRevision:async()=>scenario==="stale"?3:2,synchronizeWrappedKey:async(owner,key)=>{assert.equal(owner,"A");assert.equal(key,snapshot.lock.wrappedKey);if(scenario==="switched")generation++;return scenario==="rotated";}},
   localStorage:{setItem:()=>stored++},normalizeLockConfig:value=>value,updateLockSummary(){},scheduleInactivityLock(){},enforceInactivityLock(){},
   lockApp:()=>locked++,toast(){},vaultLockedError:()=>Object.assign(new Error("locked"),{code:"VAULT_LOCKED"}),
   writeAuthentication:async action=>action(),chrome:{storage:{local:{set:async()=>stored++},session:{get:async()=>({lastUnlockedAt:Date.now()})}},alarms:{create:async()=>{}}},
   rememberLockConfig(){},enforceTimedLock:async()=>{},clearUnlockedSession:async()=>locked++};
  vm.createContext(box);
  const marker=ext?"function transport(owner)":"function vaultTransport(owner)";
  vm.runInContext(section(source,"async function applySynchronizedLock(",marker)+section(source,marker,ext?"// Set while this device":"// A change the server refused"),box);
  const action=box[ext?"transport":"vaultTransport"]("A").changes(20);
  if(scenario==="stable"){
   assert.equal(await action,snapshot);assert.equal(stored,1);assert.equal(locked,0);
  }else{
   const code=scenario==="rotated"?"VAULT_LOCKED":scenario==="switched"?"SESSION_CHANGED":scenario==="stale"?"VAULT_CHANGED":"ACCOUNT_MISSING";
   await assert.rejects(action,error=>error.code===code);
   if(scenario==="rotated")assert.equal(locked,1,"new-key ciphertext was returned under the old unlocked key");
   if(scenario==="switched"||scenario==="missing"||scenario==="stale")assert.equal(stored,0,"stale snapshot changed account settings");
  }
  assert.deepEqual(calls,["/api/v1/bootstrap?since=20"],"routine sync split metadata and ciphertext into independent reads");
 }
 console.log("both clients: routine sync uses a revision-fenced snapshot; rotation, account switches and missing accounts refuse stale results");
})().catch(error=>{console.error(error);process.exitCode=1;});
