// Real web app tabs share a database. Hold a successful rotation response while another tab submits a secret.
const {chromium}=require("playwright"),assert=require("node:assert/strict");
const [label,port]=process.argv.slice(2),API=`http://localhost:${process.env.API_PORT||18080}`,base=`http://localhost:${port}/lockstep/`;
const PASS="concurrency-passphrase-long",b64=o=>Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt=()=>{const iat=Math.floor(Date.now()/1000);return `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Test",iat,exp:iat+3600})}.sig`};
async function manual(page){
 await page.click("#open-add");await page.click("#open-manual");
 await page.fill("#manual-issuer","Concurrent");await page.fill("#manual-account","user@example.com");await page.fill("#manual-secret","GEZDGNBVGY3TQOJQ");
}
(async()=>{
 await fetch(`${API}/__control?reset=1`);const browser=await chromium.launch();let release;
 try{
  const context=await browser.newContext({serviceWorkers:"block",acceptDownloads:true});
  await context.route("https://accounts.google.com/**",r=>r.fulfill({contentType:"application/javascript",body:"window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};"}));
  const a=await context.newPage();const errors=[];a.on("pageerror",e=>errors.push(e.message));await a.goto(base);await a.waitForTimeout(800);
  await a.evaluate(t=>onGoogleCredential({credential:t}),jwt());await a.waitForSelector("#lock-dialog[open]");
  await a.fill("#lock-passcode",PASS);await a.fill("#lock-confirm",PASS);await a.click("#lock-form button[type=submit]");
  await a.waitForFunction(()=>!document.getElementById("lock-dialog").open);
  await a.evaluate(async()=>{await addOtpUri("otpauth://totp/Initial:user?secret=JBSWY3DPEHPK3PXP&issuer=Initial");await loadEntries(true)});
  const b=await context.newPage();b.on("pageerror",e=>errors.push(e.message));await b.goto(base);await b.waitForSelector("#locked:not(.hidden)");
  await b.fill("#unlock-passcode",PASS);await b.click("#unlock-form button[type=submit]");await b.waitForSelector("#entries .entry:not(.entry-skel)");
  let reached;const barrier=new Promise(r=>reached=r),held=new Promise(r=>release=r);
  await a.route(`${API}/api/v1/vault/rotate`,async route=>{const response=await route.fetch();reached();await held;await route.fulfill({response})});
  await a.click("#open-settings");await a.click("#settings-key-rotate");await a.waitForSelector("#confirm-dialog[open]");
  await a.fill("#confirm-passkey",PASS);await a.click("#confirm-accept");
  let timer;try{await Promise.race([barrier,new Promise((_,reject)=>timer=setTimeout(()=>reject(new Error("Rotation response not reached")),15000))])}finally{clearTimeout(timer)}
  await manual(b);await b.click("#manual-form button[type=submit]");
  await b.waitForFunction(()=>document.getElementById("manual-error").textContent.includes("another tab"));
  assert.equal(await b.inputValue("#manual-secret"),"GEZDGNBVGY3TQOJQ");
  assert.ok(await b.$eval("#manual-dialog",n=>n.open));assert.equal(await b.evaluate(()=>LockstepVault.pendingCount("user-1")),0);
  release();await a.waitForFunction(()=>document.getElementById("toast").textContent.includes("rotated to version 2"),null,{timeout:30000});
  await b.evaluate(()=>document.getElementById("manual-dialog").close());await b.click("#lock-now");
  await b.fill("#unlock-passcode",PASS);await b.click("#unlock-form button[type=submit]");await b.waitForSelector("#entries .entry:not(.entry-skel)");
  await manual(b);await b.click("#manual-form button[type=submit]");
  await b.waitForFunction(()=>document.querySelectorAll("#entries .entry:not(.entry-skel)").length===2);
  const rows=await b.evaluate(()=>LockstepVault.listEntries("user-1"));assert.ok(rows.every(e=>!e.error&&e.keyVersion===2));assert.deepEqual(errors,[]);
  // A real newer Google sign-in in B must survive A's delayed authentication failure.
  let releaseOld,oldReached;const oldBarrier=new Promise(r=>oldReached=r),oldHeld=new Promise(r=>releaseOld=r);
  await a.route(`${API}/api/v1/audit-old-session`,async route=>{
   if(route.request().method()==="OPTIONS")return route.fulfill({status:204,headers:{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET, OPTIONS","Access-Control-Allow-Headers":"authorization,content-type,x-lockstep-client,x-lockstep-session,x-lockstep-subject"}});
   oldReached();await oldHeld;await route.fulfill({status:401,headers:{"Access-Control-Allow-Origin":"*"},contentType:"application/json",body:JSON.stringify({code:"SESSION_REVOKED",error:"Old session revoked"})});
  });
  await a.evaluate(()=>{window.oldAuthenticationRequest=authenticatedFetch("/api/v1/audit-old-session").then(()=>"accepted",e=>e.code)});
  await oldBarrier;
  try{await b.evaluate(t=>onGoogleCredential({credential:t}),jwt())}finally{releaseOld()}
  assert.equal(await a.evaluate(()=>oldAuthenticationRequest),"SESSION_CHANGED");
  assert.ok(await b.evaluate(()=>appSessionToken()));
  await context.setOffline(true);
  await b.click("#sign-out");await b.click("#confirm-accept");
  await b.waitForSelector("#signed-out:not(.hidden)");
  await a.waitForFunction(()=>!state.subject&&!LockstepVault.isUnlocked("user-1"));
  assert.equal(await a.locator("#entries .code").count(),0);
  assert.equal(await a.evaluate(()=>LockstepVault.localEncryptedEntries("user-1").then(rows=>rows.length)),0);
  console.log(`[${label}] cross-tab local erasure clears codes and locks the other tab`);
  console.log(`[${label}] concurrent add refused with inputs retained; rotation and subsequent unlock/add succeeded`);
 }finally{release?.();await browser.close()}
})().catch(e=>{console.error(`[${label}] FAILED`,e);process.exit(1)});
