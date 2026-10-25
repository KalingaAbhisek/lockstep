const fs=require("node:fs"),path=require("node:path"),vm=require("node:vm"),assert=require("node:assert/strict");
const root=path.resolve(__dirname,"../..");
const watchdog=setTimeout(()=>{console.error("Import staging checks did not finish");process.exit(1);},10000);
function part(source,start,end){const offset=source.indexOf(start);assert(offset>=0,start);const stop=source.indexOf(end,offset);assert(stop>offset,end);return source.slice(offset,stop);}
function dom(){const nodes=new Map();return id=>{
 if(!nodes.has(id))nodes.set(id,{value:"",textContent:"",disabled:false,open:false,classList:{add(){},remove(){},toggle(){},contains:()=>false},focus(){},
  showModal(){this.open=true;},close(){this.open=false;this.onclose?.();}});
 return nodes.get(id);
};}
(async()=>{
 for(const client of ["webapp","extension"]){
  const source=fs.readFileSync(path.join(root,client,client==="webapp"?"app.js":"popup.js"),"utf8");
  for(const failure of [false,true]){
   const node=dom();let releaseOld,releaseNew,attempts=0;
   const box={el:node,$:node,DOWNLOADS_WARNING:"private",hideInlineError:id=>node(id).textContent="",showInlineError:(id,message)=>node(id).textContent=message};
   vm.createContext(box);vm.runInContext(part(source,"function askBackupPassword(","function downloadFile("),box);
   const old=box.askBackupPassword({mode:"import",accept:()=>{attempts++;return new Promise((resolve,reject)=>releaseOld=()=>failure?reject(new Error("old error")):resolve("old secret"));}});
   const submit=node("backup-form").onsubmit;
   const accepting=submit({preventDefault(){}});
   // Enter must not start a second KDF while the same submit is running.
   const duplicate=submit({preventDefault(){}});
   assert.equal(attempts,1,client+" duplicated a pending password derivation");
   node("backup-cancel").onclick();assert.equal(await old,null);
   const current=box.askBackupPassword({mode:"import",accept:()=>new Promise(resolve=>releaseNew=()=>resolve("new secret"))});
   node("backup-password").value="current password";
   const currentHandler=node("backup-form").onsubmit;
   const currentSubmit=currentHandler({preventDefault(){}});
   releaseOld();await accepting;await duplicate;
   assert.equal(attempts,1,client+" duplicated a pending password derivation");
   assert.equal(node("backup-dialog").open,true,client+" cancelled decryption closed the newer dialog");
   assert.equal(node("backup-password").value,"current password");
   assert.equal(node("backup-accept").disabled,true,client+" stale completion enabled a newer pending submit");
   assert.equal(node("backup-error").textContent,"");assert.equal(node("backup-form").onsubmit,currentHandler);
   releaseNew();await currentSubmit;assert.equal(await current,"new secret");
  }
  console.log(client+": cancelled password work cannot close, reset or enable a newer dialog; duplicate submits are ignored");
 }
 const popup=fs.readFileSync(path.join(root,"extension/popup.js"),"utf8");
 for(const mode of ["backup","qr"]){
  let release,sent=0,closed=0;
  const node=dom(),barrier=new Promise(resolve=>release=resolve);
  const box={vaultViewEpoch:0,MAX_BACKUP_FILE_BYTES:8*1024*1024,$:node,settingsMessage(){},status(){},load:async()=>{},
   isEncryptedBackupText:()=>false,parseBackup:()=>["otpauth://totp/A?secret=JBSWY3DPEHPK3PXP"],
   loadVendorScript:async()=>{},LockstepImages:{load:async()=>{await barrier;return {source:{},close:()=>closed++};}},
   detectQrImage:()=>"otpauth://totp/A?secret=JBSWY3DPEHPK3PXP",requestAnimationFrame:fn=>fn(),
   send:async()=>{sent++;return {ok:true,data:{imported:1,failed:0}};}};
  vm.createContext(box);
  const start=mode==="backup"?"async function importBackup(":"async function importQrImages(";
  const end=mode==="backup"?"// Encrypted backups":"function detectQrImage(";
  vm.runInContext(part(popup,start,end),box);
  const pending=box[mode==="backup"?"importBackup":"importQrImages"]({target:{files:[{size:100,text:async()=>{await barrier;return "backup";}}],value:"file"}});
  await new Promise(resolve=>setTimeout(resolve,0));box.vaultViewEpoch++;release();await pending;
  assert.equal(sent,0,mode+" preprocessing sent secrets after the vault view changed");
  if(mode==="qr")assert.equal(closed,1,"cancelled QR decoding leaked its bitmap");
 }
 const web=fs.readFileSync(path.join(root,"webapp/app.js"),"utf8");
 let release,imported=0;
 const box={state:{vaultEpoch:0},beginVaultOperation:()=>0,assertVaultOperation:epoch=>{if(epoch!==box.state.vaultEpoch)throw Object.assign(new Error("locked"),{code:"VAULT_LOCKED"});},
  isVaultLockedError:error=>error.code==="VAULT_LOCKED",toast(){},clearToast(){},showInlineError(){},
  loadVendorScript:async()=>{},loadQrImage:async()=>({source:{},close(){}}),detectTotpQr:()=>"otpauth://totp/A?secret=JBSWY3DPEHPK3PXP",
  requestAnimationFrame:fn=>release=fn,importUris:async()=>{imported++;return {imported:1,failed:0};},closeAdd(){},loadEntries:async()=>{}};
 vm.createContext(box);vm.runInContext(part(web,"async function scanQrImage(","// Imported accounts"),box);
 const pending=box.scanQrImage({target:{files:[{}],value:"file"}});
 while(!release)await new Promise(resolve=>setTimeout(resolve,0));box.state.vaultEpoch++;release();await pending;
 assert.equal(imported,0,"web QR staging imported into a new unlock/session after its final animation frame");
 console.log("both clients: delayed file/QR staging cannot import into a newer vault context");
 for(const client of ["webapp","extension"])for(const mode of ["leave","replace"]){
  const source=fs.readFileSync(path.join(root,client,client==="webapp"?"app.js":"popup.js"),"utf8");
  const node=dom();let release;
  const box={state:{vaultEpoch:0,subject:"A"},vaultViewEpoch:0,recoveryFileRead:0,el:node,$:node,bind(){},hideInlineError(){},showInlineError(){}};
  vm.createContext(box);
  const fragment=client==="webapp"?part(source,"const MAX_RECOVERY_KEY_FILE_BYTES","async function restoreVault(")
   :part(source,"const MAX_RECOVERY_KEY_FILE_BYTES",'bind("settings-recovery-export"');
  vm.runInContext(fragment,box);
  const pending=box.loadRecoveryKeyFile({target:{files:[{size:100,name:"old.txt",text:()=>new Promise(resolve=>release=()=>resolve("LS2-M-"+"A".repeat(43)))}]}});
  if(mode==="leave"){box.state.vaultEpoch++;box.vaultViewEpoch++;}
  else await box.loadRecoveryKeyFile({target:{files:[{size:100,name:"current.txt",text:async()=>"LS2-M-"+"B".repeat(43)}]}});
  release();await pending;
  assert.equal(node("restore-key").value,mode==="leave"?"":"LS2-M-"+"B".repeat(43),client+" late recovery-file read repopulated or replaced the current form");
 }
 console.log("both clients: late recovery-file reads cannot repopulate a cleared form or replace a newer selection");
})().catch(error=>{console.error(error);process.exitCode=1;}).finally(()=>clearTimeout(watchdog));
