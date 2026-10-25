const fs=require("fs"),vm=require("vm"),path=require("path"),assert=require("node:assert/strict");
const source=fs.readFileSync(path.join(__dirname,"../../webapp/app.js"),"utf8");
(async()=>{let release,shown=0;
const box={state:{vaultEpoch:1,refreshing:false,offline:false,editing:false,subject:"A",lockConfig:{enabled:true}},
 isVaultOperational:()=>true,beginVaultOperation:()=>1,ownerSubject:()=>"A",isVaultLockedError:e=>e.code==="VAULT_LOCKED",
 el:()=>({querySelector:()=>null,childElementCount:1}),showLocked:()=>shown++,
 assertVaultOperation:epoch=>{if(epoch!==box.state.vaultEpoch)throw Object.assign(new Error("old operation"),{code:"VAULT_LOCKED"})},
 syncVault:()=>new Promise((r,reject)=>release=()=>reject(new Error("stale network failure")))};
vm.createContext(box);vm.runInContext(source.slice(source.indexOf("async function loadEntries("),source.indexOf('// "6 synchronized accounts"')),box);
const old=box.loadEntries();while(!release)await new Promise(r=>setTimeout(r,0));
box.state.vaultEpoch=2;box.state.refreshing=true;release();await old;
assert.equal(box.state.offline,false,"a stale refresh changed the new session connectivity state");
assert.equal(shown,0,"a stale refresh changed the newer session's lock screen");assert.equal(box.state.refreshing,true,"a stale refresh cleared the newer operation's busy state");
let hidden=0,cancelled=0,locked=[],waiters=[];
const login={state:{subject:"A",vaultEpoch:0},crypto:{randomUUID:()=>String(++cancelled)},SESSION_REVOKED_NOTICE_KEY:"notice",
 tokenClaims:token=>token==="invalid"?null:{sub:token,name:token},toast:()=>{},showLoader:()=>{},hideLoader:()=>hidden++,
 cancelVaultOperations:()=>{login.state.vaultEpoch++;login.state.refreshing=false;},clearUnlockedSession:()=>locked.push(login.state.subject),closeVaultSurfaces:()=>{},
 el:()=>({replaceChildren(){},value:""}),localStorage:{setItem(){},removeItem(){}},sessionStorage:{setItem(){}},clearToast:()=>{},scheduleGoogleSessionExpiry:()=>{},
 registerAppSession:()=>new Promise((resolve,reject)=>waiters.push({resolve,reject})),showApp:async()=>{},signOut:()=>{throw Error("stale sign-in signed out newer session")}};
vm.createContext(login);vm.runInContext(source.slice(source.indexOf("async function onGoogleCredential("),source.indexOf("// Resetting the vault")),login);
const first=login.onGoogleCredential({credential:"A"}),second=login.onGoogleCredential({credential:"B"});
waiters[0].reject(Object.assign(new Error("superseded"),{code:"SESSION_CHANGED"}));await first;assert.equal(hidden,0);
waiters[1].resolve("session-b");await second;assert.equal(hidden,1);assert.equal(login.state.subject,"B");assert.equal(login.state.vaultEpoch,2);assert.deepEqual(locked,["A"]);
await login.onGoogleCredential({credential:"invalid"});assert.equal(login.state.subject,"B");
console.log("webapp: stale refresh cannot change the current session's screen or busy state");
const popup=fs.readFileSync(path.join(__dirname,"../../extension/popup.js"),"utf8");
for (const route of ["showLocked", "showSignedOut"]) {
 let finish,rendered=0,cleared=0,editClassCleared=false;
 const nodes=new Map();
 const node=id=>{
  if(!nodes.has(id))nodes.set(id,{classList:{add(){},remove(){},contains:()=>true,toggle(){}},
   replaceChildren(){if(id==="entries")cleared++;},querySelector:()=>null,reset(){},focus(){},value:"",textContent:""});
  return nodes.get(id);
 };
 const box={vaultViewEpoch:0,entries:[{id:"old"}],originalEntries:new Map([["old",{secret:"draft"}]]),
  refreshing:false,editing:false,draggedId:"old",syncFollowTimer:1,clearTimeout(){},
  $:node,document:{body:{classList:{remove:name=>{if(name==="editing")editClassCleared=true;}}},querySelectorAll:()=>[]},status(){},toast(){},setAuthenticated(){},animateView(){},
  renderEntries:()=>rendered++,send:()=>new Promise(resolve=>finish=resolve)};
 vm.createContext(box);
 vm.runInContext(popup.slice(popup.indexOf("function clearVaultView("),popup.indexOf("async function showSettings(")),box);
 vm.runInContext(popup.slice(popup.indexOf("async function load(force"),popup.indexOf('// "Synchronizing')),box);
 const pending=box.load();box[route]();box.refreshing=true;
 finish({ok:true,data:[{id:"old",code:"123456"}]});
 assert.equal(await pending,false);assert.equal(box.entries.length,0);assert.equal(box.originalEntries.size,0);
 assert(cleared>0);assert.equal(rendered,0,"stale extension reply rendered decrypted data");
 assert(editClassCleared,"locking/sign-out left the signed-out screen hidden by edit-mode CSS");
 assert.equal(box.refreshing,true,"old extension load cleared a newer operation's busy flag");
}
for (const code of [null,"VAULT_LOCKED","SESSION_REVOKED"]) {
 let finish,routed=0;
 const box={vaultViewEpoch:0,chrome:{runtime:{sendMessage:()=>new Promise(resolve=>finish=resolve)}},
  showLocked:()=>routed++,showSignedOut:()=>routed++,status(){}};
 vm.createContext(box);
 vm.runInContext(popup.slice(popup.indexOf("async function send("),popup.indexOf("let toastTimer")),box);
 const pending=box.send("LIST_ENTRIES");box.vaultViewEpoch++;
 finish(code?{ok:false,code,error:"stale"}:{ok:true,data:[{code:"123456"}]});
 assert.equal((await pending).code,"VIEW_CHANGED");assert.equal(routed,0,"a stale extension response changed the newer screen");
}
console.log("extension: lock/sign-out clear decrypted rows and edit state; stale replies cannot render or reroute newer views");
{
 const completions=[];
 const view=()=>{const classes=new Set();return {classList:{add:c=>classes.add(c),remove:c=>classes.delete(c),contains:c=>classes.has(c)},
  animate:()=>({finished:new Promise(resolve=>completions.push(resolve)),cancel(){}})};};
 const from=view(),to=view(),main=view();
 const box={vaultViewEpoch:0,navigating:false,matchMedia:()=>({matches:false}),document:{querySelector:()=>main}};
 vm.createContext(box);
 vm.runInContext(popup.slice(popup.indexOf("async function transitionViews("),popup.indexOf("function animateView(")),box);
 const moving=box.transitionViews(from,to,"forward");box.vaultViewEpoch++;
 to.classList.add("hidden");from.classList.remove("hidden");
 completions.forEach(resolve=>resolve());await moving;
 assert.equal(from.classList.contains("hidden"),false,"an old settings animation hid the newer lock screen");
 assert.equal(to.classList.contains("hidden"),true);assert.equal(box.navigating,false);
}
console.log("extension: interrupted settings animations preserve the current lock screen");
for (const method of ["showSettings","hideSettings"]) {
 let release;
 const nodes=new Map(),get=id=>{
  if(!nodes.has(id)){const classes=new Set();nodes.set(id,{classList:{add:c=>classes.add(c),remove:c=>classes.delete(c),toggle:(c,on)=>on?classes.add(c):classes.delete(c),contains:c=>classes.has(c)}});}
  return nodes.get(id);
 };
 const box={vaultViewEpoch:0,navigating:false,isAuthenticated:true,editing:false,$:get,
  animateTitle(){},settingsMessage(){},transitionViews:()=>new Promise(resolve=>release=resolve)};
 vm.createContext(box);
 const start=method==="showSettings"?"async function showSettings(":"async function hideSettings(";
 const end=method==="showSettings"?"function setAuthenticated(":"async function transitionViews(";
 vm.runInContext(popup.slice(popup.indexOf(start),popup.indexOf(end)),box);
 const pending=box[method]();box.vaultViewEpoch++;
 // Recovery owns the navigation buttons now; neither should be exposed by an old callback.
 get("settings").classList.add("hidden");get("settings-back").classList.add("hidden");
 release();await pending;
 assert(get("settings").classList.contains("hidden"),method+" exposed settings after the vault view changed");
 assert(get("settings-back").classList.contains("hidden"),method+" exposed navigation after the vault view changed");
}
{
 let release,loads=0;
 const box={vaultViewEpoch:0,refreshing:false,editing:false,localRefreshing:false,
  send:()=>new Promise(resolve=>release=resolve),handleSessionProblem:()=>false,load:()=>loads++};
 vm.createContext(box);
 vm.runInContext(popup.slice(popup.indexOf("async function refreshLocalCodes("),popup.indexOf("// QR libraries")),box);
 const pending=box.refreshLocalCodes();box.vaultViewEpoch++;box.localRefreshing=true;
 release({ok:false,code:"VIEW_CHANGED"});await pending;
 assert.equal(loads,0,"stale local-code refresh started a load in another vault view");
 assert.equal(box.localRefreshing,true,"stale local-code refresh cleared the newer busy flag");
}
console.log("extension: stale settings and local-code callbacks leave newer views and busy flags alone");
})().catch(e=>{console.error(e);process.exitCode=1;});
