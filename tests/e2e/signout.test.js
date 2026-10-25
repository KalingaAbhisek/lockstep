const fs=require("fs"),vm=require("vm"),assert=require("node:assert/strict");
const source=fs.readFileSync(require("path").join(__dirname,"../../extension/service-worker.js"),"utf8");
function section(a,b){return source.slice(source.indexOf(a),source.indexOf(b,source.indexOf(a)));}
(async()=>{for(const failure of [false,true]){
let local={vaultSubject:"A",appSessionId:"session"},erased=false;
const box={chrome:{storage:{local:{get:async()=>({...local}),remove:async keys=>{for(const k of keys)delete local[k];}},session:{clear:async()=>{}}}},
LockstepVault:{lock:()=>{},clearSubject:async owner=>{assert.equal(owner,"A");if(failure)throw Error("disk failed");erased=true;}},forgetRecentReads:()=>{},stopPendingSync:async()=>{}};
vm.createContext(box);vm.runInContext(section("let authenticationGeneration","let tokenRefreshPromise")+section("async function invalidateAuthentication(","async function subject("),box);
if(failure){await assert.rejects(box.invalidateAuthentication("",null,true));assert.equal(local.vaultSubject,"A");}
else{await box.invalidateAuthentication("",null,true);assert(erased);assert.equal(local.vaultSubject,undefined);}
}
const popup=fs.readFileSync(require("path").join(__dirname,"../../extension/popup.js"),"utf8");
let confirmed=false,sent=0,shown=0;
const ui={chrome:{storage:{local:{get:async()=>({vaultSubject:"A",appSessionId:"session"})}}},confirmAction:async opts=>{assert.equal(opts.title,"Sign out?");assert(opts.message.includes("permanently lost"));return confirmed;},send:async(type,payload)=>{assert.equal(type,"LOGOUT");assert.equal(payload.authentication.owner,"A");sent++;return {ok:true};},hideSettings:async()=>{},showSignedOut:()=>shown++,status:()=>{}};
vm.createContext(ui);vm.runInContext(popup.slice(popup.indexOf("async function signOutAndRemoveData()"),popup.indexOf('bind("settings-signout",')),ui);
await ui.signOutAndRemoveData();assert.equal(sent,0);confirmed=true;await ui.signOutAndRemoveData();assert.equal(sent,1);assert.equal(shown,1);
console.log("extension: sign-out cancellation, confirmation, local deletion and failure reporting passed");
})().catch(e=>{console.error(e);process.exitCode=1;});
