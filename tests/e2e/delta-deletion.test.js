const path=require("node:path"),assert=require("node:assert/strict"),{chromium}=require("playwright");
(async()=>{const browser=await chromium.launch();try{for(const client of ["webapp","extension"]){
 const context=await browser.newContext(),page=await context.newPage();
 await page.route("http://localhost/**",r=>r.fulfill({contentType:"text/html",body:"<!doctype html>"}));await page.goto("http://localhost/");
 await page.addScriptTag({path:process.env.VAULT_SCRIPT||path.resolve(__dirname,"../..",client,"crypto-store.js")});
 const remaining=await page.evaluate(async()=>{
  const V=LockstepVault,owner="delta-delete";
  await V.configurePassphrase(owner,"delta-deletion-passphrase");
  await V.addOtpUri(owner,"otpauth://totp/Deleted:user?secret=JBSWY3DPEHPK3PXP&issuer=Deleted");
  const rows=await V.localEncryptedEntries(owner),id=rows[0].id;
  await V.synchronize(owner,{put:async(id,payload)=>({id,...payload}),changes:async()=>({entries:rows,full:true,cursor:Date.now()})});
  // A deletion commits between the backend's changed-entry and tombstone queries.
  await V.synchronize(owner,{changes:async since=>{if(since===null)throw Error("Test did not establish a delta cursor");return {entries:rows,deletedIds:[id],full:false,cursor:Date.now()}}});
  return (await V.listEntries(owner)).length;
 });
 assert.equal(remaining,0,client+": overlapping delta resurrected a deleted entry");
 await context.close();console.log(client+": deletion wins over a changed entry in the same delta");
}}finally{await browser.close()}})().catch(error=>{console.error(error);process.exitCode=1});
