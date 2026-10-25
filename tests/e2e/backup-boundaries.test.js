const fs=require("fs"),vm=require("vm"),path=require("path"),assert=require("node:assert/strict"),{chromium}=require("playwright");
const root=path.resolve(__dirname,"../..");
function fn(s,name){const start=s.indexOf("function "+name+"(");let depth=0;for(let i=s.indexOf("{",start);i<s.length;i++){if(s[i]==="{")depth++;if(s[i]==="}"&&!--depth)return s.slice(start,i+1);}}
(async()=>{
const worker=fs.readFileSync(path.join(root,"extension/service-worker.js"),"utf8");
for(const mode of ["switch","lock","invalid"]){let current={owner:"A",generation:1},written=[],locked=false;
const box={authenticationTransition:false,authenticationSnapshot:async()=>({...current}),authenticationMatches:async s=>s.generation===current.generation,coded:(code,message)=>Object.assign(new Error(message),{code}),synchronize:async()=>{},LockstepVault:{isUnlocked:()=>!locked,addOtpUri:async owner=>{written.push(owner);if(mode==="switch")current={owner:"B",generation:2};if(mode==="lock")locked=true;if(mode==="invalid")throw Error("invalid URI");}}};
vm.createContext(box);vm.runInContext("async "+fn(worker,"importEntries"),box);
if(mode==="invalid")assert.equal((await box.importEntries(["a","b"])).failed,2);
else{await assert.rejects(box.importEntries(["a","b"]),e=>["SESSION_CHANGED","VAULT_LOCKED"].includes(e.code)&&e.message.includes("1 account was imported"));assert.deepEqual(written,["A"]);}}
const web=fs.readFileSync(path.join(root,"webapp/app.js"),"utf8");
for(const mode of ["switch","lock","invalid"]){let identity={owner:"A",generation:1},locked=false,written=[];
 const box={authenticationSnapshot:()=>({...identity}),ownerSubject:()=>identity.owner,authenticationMatches:s=>s.generation===identity.generation,beginVaultOperation:()=>1,
 assertVaultOperation:()=>{if(locked)throw Object.assign(new Error("locked"),{code:"VAULT_LOCKED"})},isVaultLockedError:e=>e.code==="VAULT_LOCKED",schedulePendingSync:()=>{},syncVault:async()=>{},
 LockstepVault:{addOtpUri:async owner=>{written.push(owner);if(mode==="switch")identity={owner:"B",generation:2};if(mode==="lock")locked=true;if(mode==="invalid")throw Error("invalid URI")}}};
 vm.createContext(box);vm.runInContext("async "+fn(web,"importUris"),box);
 if(mode==="invalid")assert.equal((await box.importUris(["a","b"])).failed,2);
 else{await assert.rejects(box.importUris(["a","b"]),e=>["SESSION_CHANGED","VAULT_LOCKED"].includes(e.code)&&e.message.includes("1 account was imported"));assert.deepEqual(written,["A"]);}
}
const browser=await chromium.launch();try{for(const client of ["webapp","extension"]){
const context=await browser.newContext();const page=await context.newPage();await page.route("http://localhost/**",r=>r.fulfill({contentType:"text/html",body:"<!doctype html>"}));await page.goto("http://localhost/");await page.addScriptTag({path:path.join(root,client,"crypto-store.js")});
const source=fs.readFileSync(path.join(root,client,client==="webapp"?"app.js":"popup.js"),"utf8");const parse=fn(source,"parseBackup");
await page.addScriptTag({content:parse});
const result=await page.evaluate(async()=>{
const V=LockstepVault,subject="large-backup",pass="long-backup-passphrase";await V.configurePassphrase(subject,pass);
const issuer="😀".repeat(64);
for(let i=0;i<1000;i++)await V.addOtpUri(subject,`otpauth://totp/${encodeURIComponent(issuer+":"+"😀".repeat(120)+i)}?secret=JBSWY3DPEHPK3PXP&issuer=${encodeURIComponent(issuer)}`);
const plain=await V.exportText(subject),encrypted=await V.encryptBackup(plain,pass),restored=await V.decryptBackup(encrypted,pass);
let oversized=false;try{parseBackup(plain+"otpauth://totp/Extra:user?secret=JBSWY3DPEHPK3PXP\n")}catch{oversized=true;}
return {plainBytes:new TextEncoder().encode(plain).length,encryptedBytes:new TextEncoder().encode(encrypted).length,plain:parseBackup(plain).length,encrypted:parseBackup(restored).length,equal:plain===restored,oversized};});
assert.equal(result.plain,1000);assert.equal(result.encrypted,1000);assert(result.equal&&result.oversized);assert(result.plainBytes>2*1024*1024&&result.encryptedBytes<8*1024*1024);
// Measure the final CSS cascade, rather than obsolete palette definitions.
await page.addStyleTag({path:path.join(root,client,client==="webapp"?"styles.css":"popup.css")});
const colors=await page.evaluate(()=>{document.documentElement.dataset.theme="light";const s=getComputedStyle(document.documentElement);return [s.getPropertyValue("--muted").trim(),s.getPropertyValue("--positive").trim(),s.getPropertyValue("--surface-2").trim()||s.getPropertyValue("--field").trim(),s.getPropertyValue("--bg").trim()||s.getPropertyValue("--canvas").trim()];});
const lum=h=>{let v=[1,3,5].map(i=>parseInt(h.slice(i,i+2),16)/255).map(v=>v<=.04045?v/12.92:((v+.055)/1.055)**2.4);return v[0]*.2126+v[1]*.7152+v[2]*.0722;};
for(const [fg,bg] of [[colors[0],colors[2]],[colors[1],colors[3]]])assert((lum(bg)+.05)/(lum(fg)+.05)>=4.5);
console.log(client+": 1000-entry plaintext/encrypted backup round trips, limit rejection and light-theme contrast passed");await context.close();
}}finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
