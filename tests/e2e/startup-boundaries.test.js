const fs=require("fs"),vm=require("vm"),assert=require("node:assert/strict"),path=require("path");
function section(s,a,b){return s.slice(s.indexOf(a),s.indexOf(b,s.indexOf(a)));}
(async()=>{
for(const ext of [false,true])for(const fallback of [false,true]){
 const s=fs.readFileSync(path.join(__dirname,"../..",ext?"extension/service-worker.js":"webapp/app.js"),"utf8");
 let identity={owner:"A",subject:"A",generation:1},sent=0,switched=false;
 const box={authenticationGeneration:1,state:{bootstrapUnsupported:fallback},bootstrapUnsupported:fallback,
 authenticationSnapshot:()=>ext?Promise.resolve({...identity}):({...identity}),authenticationMatches:snapshot=>ext?Promise.resolve(snapshot.generation===identity.generation):snapshot.generation===identity.generation,
 assertSyncCooldown:()=>{},LockstepVault:{syncGeneration:()=>1,localGeneration:async()=>1,startupCursor:async()=>{identity={owner:"B",subject:"B",generation:2};switched=true;return null;}},
 api:async(url,opts)=>{if(fallback&&!switched){identity={owner:"B",subject:"B",generation:2};switched=true;}if(opts.expectedAuthentication.generation!==identity.generation)throw Object.assign(new Error("changed"),{code:"SESSION_CHANGED"});sent++;return {exists:true};}};
 vm.createContext(box);vm.runInContext(section(s,ext?"async function assertStartupAuthentication":"function assertStartupAuthentication",ext?"function transport(owner)":"function takePrefetchedVault(owner)"),box);
 await assert.rejects(box.fetchStartupState("A"),e=>e.code==="SESSION_CHANGED");assert.equal(sent,0);
 console.log((ext?"extension":"webapp")+": startup account switch refused (fallback="+fallback+")");
}
// Existing timer must defer when a later response imposes a cooldown.
const s=fs.readFileSync(path.join(__dirname,"../../webapp/app.js"),"utf8");let callback,sends=0,delay;
const box={state:{subject:"A",pendingSyncTimer:null,pendingSyncRunning:false},navigator:{onLine:true},appSessionToken:()=>true,setTimeout:(fn,ms)=>{callback=fn;delay=ms;return 1},clearTimeout:()=>{},flushPendingVault:async()=>sends++,LockstepVault:{pendingCount:async()=>0}};
box.authenticationSnapshot=()=>({subject:box.state.subject});box.authenticationMatches=snapshot=>snapshot.subject===box.state.subject;
vm.createContext(box);vm.runInContext(section(s,"const syncRetryStates","async function api(path")+section(s,"function schedulePendingSync(","async function syncVault("),box);
box.schedulePendingSync(10000);box.recordSyncFailure("A",{retryAfterMillis:60000});await callback();assert.equal(sends,0);assert(delay>59000);console.log("webapp: existing retry timer respects new cooldown");
const retry={state:{subject:"A",pendingSyncTimer:null,pendingSyncRunning:false},navigator:{onLine:true},
 appSessionToken:()=>true,authenticationSnapshot:()=>({subject:retry.state.subject}),authenticationMatches:snapshot=>snapshot.subject===retry.state.subject,
 setTimeout:(fn,ms)=>{delay=ms;return 1},clearTimeout(){},updateAccountSummary(){},vaultTransport:()=>({}),
 LockstepVault:{pendingCount:async()=>1,flushOutbox:async()=>{retry.recordSyncFailure("A",{retryAfterMillis:60000});throw Object.assign(new Error("rate limited"),{status:429});}}};
vm.createContext(retry);vm.runInContext(section(s,"const syncRetryStates","async function api(path")+section(s,"async function flushPendingVault(","async function syncVault("),retry);
await retry.runPendingSyncRetry();assert(retry.retryDelay("A")>59000,"a failed background upload discarded Retry-After");assert(delay>59000);
retry.state.pendingChanges=7;retry.flushPendingVault=async()=>{retry.state.subject="B";return {pending:0};};
await retry.runPendingSyncRetry(); // A's cooldown defers; clear it for the next ownership test.
vm.runInContext('syncRetryStates.clear()',retry);await retry.runPendingSyncRetry();
assert.equal(retry.state.pendingChanges,7,"an old background upload overwrote the newer account's pending count");
console.log("webapp: failed background upload retains Retry-After and cannot publish counts under a newer account");
const worker=fs.readFileSync(path.join(__dirname,"../../extension/service-worker.js"),"utf8");let extSent=0,extDelay=0;
const extBox={pendingSyncPromise:null,pendingSyncTimeout:null,PENDING_SYNC_ALARM:"retry",clearTimeout:()=>{},chrome:{alarms:{clear:async()=>{}}},subject:async()=>"A",LockstepVault:{pendingCount:async()=>1,flushOutbox:async()=>extSent++},retryDelay:()=>60000,schedulePendingSync:async delay=>{extDelay=delay;}};
vm.createContext(extBox);vm.runInContext(section(worker,"async function retryPendingSync()","chrome.runtime.onMessage.addListener"),extBox);
await extBox.retryPendingSync();assert.equal(extSent,0);assert.equal(extDelay,60000);console.log("extension: retry alarm respects cooldown before sending");
})().catch(e=>{console.error(e);process.exitCode=1;});
