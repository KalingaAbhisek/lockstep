const API_PORT=Number(process.env.API_PORT||8080),API_ORIGIN=`http://localhost:${API_PORT}`;
const CSP=`default-src 'self'; script-src 'self' 'wasm-unsafe-eval' 'sha256-yLtySBGrbFP+zsOIJjtRynJeo4M0W8BOZsd+msHVU+0=' 'sha256-9G+ZEjK4FvicPqy823ES862ixLp1UvIjPXLNCCAhtQM=' https://accounts.google.com/gsi/client; style-src 'self' https://accounts.google.com/gsi/style 'sha256-RU4sU0AaS8IBGZx8XrGt/pa9A5SLA3dQszGeqT5L3Kw='; connect-src 'self' ${API_ORIGIN} https://accounts.google.com/gsi/; frame-src https://accounts.google.com/gsi/; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; worker-src 'self'; manifest-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; require-trusted-types-for 'script'`; // Trusted Types enforced in tests (report-only in production)
// Mock Lockstep API + static server. Usage: node mock-server.js <webappDir> <staticPort>  (API on $API_PORT, default 8080)
// Prints "ready" once both servers are listening; exits with an error if a port is taken.
const http=require("http"),fs=require("fs"),path=require("path");
const { randomUUID } = require("node:crypto");
const liveClients = new Set();
function notifyLiveClients() {
  for (const client of liveClients) {
    // Per-client mode (like the real API): one session slot per client type; a new sign-in ends only that type's.
    const revoked = db.perClient ? client.token !== db.sessions[client.type] : client.token !== db.session;
    client.res.write(`event: ${revoked ? "session" : "change"}\ndata: {}\n\n`);
    if (revoked) client.res.end();
  }
}
const [webDir,staticPort]=[process.argv[2],Number(process.argv[3]||5173)];
let LATENCY=Number(process.env.LATENCY||200);
const freshDb=()=>({exists:false,lock:{enabled:false,timeoutSeconds:0,lockOnScreenLock:false,wrappedKey:null},entries:new Map(),tombstones:new Map(),session:null,sessions:{web:null,extension:null},perClient:false,passcodeSeen:0,revision:0,signedOutAll:0,staleNextAdd:false});
let db=freshDb();
// "argon2idWrapping" is announced unless ARGON2ID=0 or after /__control?argon2id=0 (like ARGON2ID_WRAPPING on the API, on by default).
let argon2idFeature=process.env.ARGON2ID!=="0";
// Like REQUIRE_VAULT_REVISION (on by default): replacing a stored wrapped key without expectedRevision is refused.
let outdatedRefused=0; // kept across /__control?reset=1; run-all.js fails a scenario where a current app was refused
const outdated=(res)=>{outdatedRefused++;return send(res,409,{code:"VAULT_CHANGED",error:"This version of Lockstep is out of date. Update it, then change your passphrase again."});};
// The vault revision is part of the lock settings on current servers; "old server" mode (nobootstrap) has none.
const lockView=()=>db.noBootstrap?db.lock:{...db.lock,vaultRevision:db.revision};
const conflict=(res,message)=>send(res,409,{code:"VAULT_CHANGED",error:message||"Your passphrase or recovery key changed on another device. Unlock with the current passphrase and try again."});
const calls=[];
const types={".js":"application/javascript",".css":"text/css",".html":"text/html",".json":"application/json",".png":"image/png",".webmanifest":"application/manifest+json",".svg":"image/svg+xml"};
http.createServer((req,res)=>{
  if(req.url.startsWith("/lockstep/api/")){ // same-origin API proxy, like nginx with LOCKSTEP_USE_API_PROXY=true
    const target=API_ORIGIN+req.url.slice("/lockstep".length);
    const chunks=[];req.on("data",c=>chunks.push(c));req.on("end",()=>{
      const preq=http.request(target,{method:req.method,headers:{...req.headers,host:`localhost:${API_PORT}`}},pres=>{
        const headers={...pres.headers};
        if(headers["set-cookie"])headers["set-cookie"]=headers["set-cookie"].map(c=>c.replace("Path=/api","Path=/lockstep/api"));
        res.writeHead(pres.statusCode,headers);pres.pipe(res);});
      res.on("close",()=>preq.destroy());
      preq.on("error",()=>{if(!res.headersSent)res.writeHead(502);res.end();});preq.end(Buffer.concat(chunks));});
    return;
  }
  let p=decodeURIComponent(new URL(req.url,"http://x").pathname);
  if(!p.startsWith("/lockstep/")){res.writeHead(404);return res.end();}
  p=p.slice("/lockstep".length); if(p==="/")p="/index.html";
  const file=path.join(webDir,p);
  fs.readFile(file,(err,data)=>{ if(err){res.writeHead(404);return res.end();} res.writeHead(200,{"Content-Type":types[path.extname(file)]||"application/octet-stream","Cache-Control":"no-cache","Cross-Origin-Resource-Policy":"same-origin",...(process.env.CSP?{"Content-Security-Policy":CSP}:{})}); res.end(data);});
}).listen(staticPort,()=>listening("static"));
const started=new Set();
function listening(name){started.add(name);if(started.size===2)console.log("ready");}
process.on("uncaughtException",(error)=>{console.error(`mock server failed: ${error.message}`);process.exit(1);});
// Destructive requests need a Google ID token issued in the last five minutes, like the real API.
function recentGoogle(req){
  const match=/^Bearer (.+)$/.exec(req.headers.authorization||"");
  if(!match)return false;
  try{const claims=JSON.parse(Buffer.from(match[1].split(".")[1],"base64url").toString());return Boolean(claims.iat&&Date.now()-claims.iat*1000<300000);}catch{return false;}
}
const reauth=(res)=>send(res,403,{code:"REAUTH_REQUIRED",error:"Confirm it is you: sign in with Google again to continue."});
function send(res,status,body){res.writeHead(status,{"Content-Type":"application/json","Access-Control-Allow-Origin":"*"});res.end(body===undefined?"":JSON.stringify(body));}
function finishSessionChange(res){
  if(process.env.LIVE_CHANGES!=="1")return send(res,204);
  // Firestore can notify other clients before the initiating HTTP request acknowledges its commit.
  notifyLiveClients();return setTimeout(()=>send(res,204),400);
}
function entryResponse(id,p){return {id,issuer:p.issuer,accountName:p.accountName,encryptedSecret:p.encryptedSecret,secretIv:p.secretIv,keyVersion:p.keyVersion,algorithm:p.algorithm,digits:p.digits,periodSeconds:p.periodSeconds,createdAtEpochMillis:p.createdAtEpochMillis,updatedAtEpochMillis:Date.now(),mutationId:p.mutationId,encryptedLabel:p.encryptedLabel??null,labelIv:p.labelIv??null};}
function putEntry(id,p){db.exists=true;db.tombstones.delete(id);const e=entryResponse(id,p);db.entries.set(id,e);return e;}
// Like FirestoreAuthenticatorEntryRepository: an edit names the version it was made from (baseMutationId) and is
// refused when the entry changed (CONFLICT) or was deleted (DELETED) since; oversized ciphertext is invalid (400).
function refusal(id,p){
  const stored=db.entries.get(id);
  if(db.tombstones.has(id))return {status:400,code:"DELETED",message:"This account was removed on another device, so the change was discarded."};
  if(stored&&stored.mutationId===p.mutationId)return null; // retry of an applied change
  if(!stored&&db.limitNextAdd){db.limitNextAdd=false;return {status:400,code:"ACCOUNT_LIMIT",message:"You can store at most 1000 authenticator accounts"};}
  if(Buffer.from(String(p.encryptedSecret||""),"base64").length>1024)return {status:400,code:null,message:"Encrypted secret has an invalid size"};
  // Like the API: a new account must use the current recovery key (after a rotation elsewhere it is STALE_KEY).
  if(!stored&&!p.baseMutationId&&db.lock.wrappedKey&&Number(p.keyVersion)<Number(db.lock.wrappedKey.currentVersion))return {status:400,code:"STALE_KEY",message:"Your recovery key was changed on another device, so an account added with the old key could not be saved. Unlock Lockstep and add it again."};
  if(p.baseMutationId&&!stored)return {status:400,code:"DELETED",message:"This account was removed on another device, so the change was discarded."};
  if(p.baseMutationId&&stored.mutationId!==p.baseMutationId)return {status:400,code:"CONFLICT",message:"This account was changed on another device at the same time. The newer version was kept."};
  // REQUIRE_EDIT_BASE (on by default): an update of an existing entry must name the version it was made from.
  if(!p.baseMutationId&&stored&&process.env.REQUIRE_EDIT_BASE!=="0")return {status:400,code:"STALE_KEY",message:"This version of Lockstep is out of date and cannot save changes to existing accounts safely. Update it, then make the change again."};
  return null;
}
function deleteEntry(id){db.entries.delete(id);db.tombstones.set(id,Date.now());}
http.createServer((req,res)=>{
  if(req.method==="OPTIONS"){res.writeHead(204,{"Access-Control-Allow-Origin":"*","Access-Control-Allow-Methods":"GET,POST,PUT,DELETE,OPTIONS","Access-Control-Allow-Headers":"Authorization,Content-Type,X-Lockstep-Client,X-Lockstep-Session,X-Lockstep-Subject"});return res.end();}
  if(db.down&&!req.url.startsWith("/__control")){req.socket.destroy();return;}
  let body="";req.on("data",c=>body+=c);req.on("end",()=>setTimeout(()=>{
    const url=new URL(req.url,"http://x"),p=url.pathname,m=req.method;
    if(p==="/__page"){res.writeHead(200,{"Content-Type":"text/html"});return res.end("<!doctype html><title>page</title><p>page</p>");}
    if(p==="/__control"){ if(url.searchParams.get("reset")){db=freshDb();calls.length=0;}
      if(url.searchParams.has("closeStreams"))for(const client of liveClients)client.res.end();
      if(url.searchParams.get("staleNextAdd"))db.staleNextAdd=true;
      if(url.searchParams.get("limitNextAdd"))db.limitNextAdd=true;
      if(url.searchParams.has("latency"))LATENCY=Number(url.searchParams.get("latency"));
      if(url.searchParams.has("argon2id"))argon2idFeature=url.searchParams.get("argon2id")==="1";
      if(url.searchParams.get("remoteDelete")){const id=[...db.entries.keys()].at(-1);db.entries.delete(id);db.tombstones.set(id,Date.now());}
      if(url.searchParams.get("remoteRename")){const e=[...db.entries.values()][0];e.issuer="Renamed elsewhere";e.encryptedLabel=null;e.labelIv=null;e.mutationId=randomUUID();e.updatedAtEpochMillis=Date.now();}
      if(url.searchParams.get("conflictNextRotate"))db.conflictNextRotate=true;
      if(url.searchParams.get("remoteTouch")){const e=[...db.entries.values()][0];e.mutationId=randomUUID();e.updatedAtEpochMillis=Date.now();}
      if(url.searchParams.has("advanceVaultRevision"))db.revision++;
      if(url.searchParams.get("clearCalls"))calls.length=0;
      if(url.searchParams.get("nobootstrap"))db.noBootstrap=true;
      if(url.searchParams.has("down"))db.down=url.searchParams.get("down")==="1";
      // blockClient=web|extension|none: that client cannot reach the server (connections dropped, its live
      // channel closed), as if it were offline, while the other client keeps working.
      if(url.searchParams.has("blockClient")){db.blockClient=url.searchParams.get("blockClient");for(const c of [...liveClients])if(c.type===db.blockClient){liveClients.delete(c);c.res.destroy();}}
      // failNext=N&failClient=web|extension: that client's next N reads of /api/v1/bootstrap, /api/v1/account or
      // /api/v1/lock fail with a temporary error (503 + Retry-After), like a busy or briefly unavailable API.
      if(url.searchParams.has("failNext")){db.failNext=Number(url.searchParams.get("failNext"));db.failClient=url.searchParams.get("failClient")||"extension";}
      if(url.searchParams.get("revoke"))db.session="replaced-by-another-device";
      if(url.searchParams.get("perClientSessions")){db.perClient=true;db.sessions={web:null,extension:null};}
      // wipeVault: the server's data is deleted outside Lockstep (for example in the Firebase console); the
      // revision starts again from 0, but the signed-in session stays valid.
      if(url.searchParams.get("wipeVault")){const {session,sessions,perClient}=db;db=freshDb();Object.assign(db,{session,sessions,perClient});}
      return send(res,200,{calls,entries:[...db.entries.values()].map(e=>e.issuer+":"+e.accountName),encrypted:[...db.entries.values()].filter(e=>e.encryptedLabel).length,lock:db.lock.enabled,lockTimeout:db.lock.timeoutSeconds,lockOnScreenLock:db.lock.lockOnScreenLock,keyVersion:db.lock.wrappedKey?.currentVersion??null,wrappedKey:db.lock.wrappedKey?.wrappedMasterKey??null,revision:db.revision,exists:db.exists,passcodeSeen:db.passcodeSeen,session:db.session,sessions:db.sessions,perClient:db.perClient,cookieSessions:db.cookieSessions||0,signedOutAll:db.signedOutAll,resets:db.resets||0,
        wrapping:db.lock.wrappedKey?.wrapping??null,outdatedRefused,liveConnections:liveClients.size,mutations:[...db.entries.values()].map(e=>e.mutationId)});}
    calls.push(m+" "+p+(url.search||""));
    if(body&&/"passcode"/.test(body)&&p!=="/api/v1/lock/verify")db.passcodeSeen++;
    const json=body?JSON.parse(body):null;
    if(p==="/api/v1/config")return send(res,200,{googleClientId:"test-client"});
    const clientType=req.headers["x-lockstep-client"]==="extension"?"extension":"web";
    if(db.blockClient===clientType){req.socket.destroy();return;}
    if(clientType===db.failClient&&db.failNext>0&&m==="GET"&&["/api/v1/bootstrap","/api/v1/account","/api/v1/lock"].includes(p)){
      db.failNext--;res.setHeader("Retry-After","1");
      return send(res,503,{code:"BACKEND_UNAVAILABLE",error:"Lockstep is temporarily unavailable. Please try again in a moment."});
    }
    if(p==="/api/v1/session"&&m==="POST"&&db.perClient){ // each sign-in gets a new random token in its own slot
      const token=`session-${clientType}-${randomUUID()}`;db.sessions[clientType]=token;
      // Like VaultChangeController's session listener: the replaced session's live stream ends at once.
      if(process.env.LIVE_CHANGES==="1")setImmediate(notifyLiveClients);
      if(req.headers["x-lockstep-session-mode"]==="cookie"&&clientType==="web"){db.cookieSessions=(db.cookieSessions||0)+1;res.setHeader("Set-Cookie",`lockstep_session=${token}; Path=/api; HttpOnly; SameSite=Strict`);return send(res,200,{sessionToken:null,clientType,expiresAtEpochMillis:Date.now()+30*864e5});}
      return send(res,200,{sessionToken:token,clientType,expiresAtEpochMillis:Date.now()+30*864e5});}
    if(p==="/api/v1/session"&&m==="POST"){db.session="session-token";
      if(req.headers["x-lockstep-session-mode"]==="cookie"){db.cookieSessions=(db.cookieSessions||0)+1;res.setHeader("Set-Cookie","lockstep_session=session-token; Path=/api; HttpOnly; SameSite=Strict");return send(res,200,{sessionToken:null,clientType:"web",expiresAtEpochMillis:Date.now()+30*864e5});}
      return send(res,200,{sessionToken:"session-token",clientType:"web",expiresAtEpochMillis:Date.now()+30*864e5});}
    const cookieToken=(/(?:^|;\s*)lockstep_session=([^;]*)/.exec(req.headers.cookie||"")||[])[1];
    const presented=req.headers["x-lockstep-session"]||cookieToken;
    if(db.perClient?(!db.sessions[clientType]||presented!==db.sessions[clientType]):(!db.session||presented!==db.session))return send(res,401,{code:"SESSION_REVOKED",error:"This Lockstep session was replaced by a login on another device."});
    if(p==="/api/v1/events"&&m==="GET"&&process.env.LIVE_CHANGES==="1"){
      // Like the real API (VaultChangeController): at most 4 live connections per account; when full,
      // the oldest connection of the same client type (else the oldest) is closed to make room. LIVE_NO_EVICT=1
      // behaves like earlier API versions: 429 with Retry-After: 60.
      if(liveClients.size>=4){
        const oldest=[...liveClients].find(c=>c.type===clientType)||[...liveClients][0];
        if(process.env.LIVE_NO_EVICT==="1"){res.setHeader("Retry-After","60");return send(res,429,{code:"RATE_LIMITED",error:"Too many live connections. Close an unused Lockstep tab and try again."});}
        liveClients.delete(oldest);oldest.res.end();
      }
      res.writeHead(200,{"Content-Type":"text/event-stream","Cache-Control":"no-store","Access-Control-Allow-Origin":"*"});
      const client={res,token:presented,type:clientType};liveClients.add(client);
      res.on("close",()=>liveClients.delete(client));res.write("event: change\ndata: {}\n\n");return;
    }
    if(process.env.LIVE_CHANGES==="1"&&m!=="GET")res.on("finish",()=>{if(res.statusCode<300)notifyLiveClients();});
    if(p==="/api/v1/session"&&m==="DELETE"){if(url.searchParams.get("all")==="true"){if(!recentGoogle(req))return reauth(res);db.signedOutAll++;db.sessions={web:null,extension:null};}else if(db.perClient)db.sessions[clientType]=null;db.session=null;return finishSessionChange(res);}
    if(p==="/api/v1/vault/rotate"&&m==="POST"){
      if(db.noBootstrap)return send(res,404,{error:"Not Found"});
      if(!recentGoogle(req))return reauth(res);
      // Match LockService's KDF validation: rotation must carry Argon2id's memory and lane parameters.
      const key=json.wrappedKey;
      const validKdf=key&&(key.wrapping==="ARGON2ID-V13/AES-256-GCM"
        ? key.iterations>=2&&key.iterations<=10&&key.memoryKiB>=19456&&key.memoryKiB<=262144&&key.parallelism>=1&&key.parallelism<=4
        : key.wrapping==="PBKDF2-SHA256/AES-256-GCM"&&key.iterations===600000&&key.memoryKiB==null&&key.parallelism==null);
      if(!validKdf)return send(res,400,{error:"Invalid wrapped vault key metadata"});
      if(db.conflictNextRotate){db.conflictNextRotate=false;return send(res,409,{code:"VAULT_CHANGED",error:"Your accounts changed on another device during the rotation. Nothing was changed; try again."});}
      const current=Object.fromEntries([...db.entries.values()].map(e=>[e.id,e.mutationId]));
      const previous=Object.fromEntries(json.previous.map(e=>[e.id,e.mutationId]));
      if(JSON.stringify(Object.entries(current).sort())!==JSON.stringify(Object.entries(previous).sort()))return send(res,409,{code:"VAULT_CHANGED",error:"Your accounts changed on another device during the rotation. Nothing was changed; try again."});
      if(json.expectedRevision==null&&db.lock.wrappedKey)return outdated(res);
      if(json.expectedRevision!=null&&json.expectedRevision!==db.revision)return conflict(res);
      if(db.lock.wrappedKey&&json.wrappedKey.currentVersion<=db.lock.wrappedKey.currentVersion)return conflict(res,"The recovery key was already rotated on another device. Lock and unlock Lockstep, then try again.");
      if(Buffer.byteLength(body)>8*1024*1024)return send(res,413,{code:"REQUEST_TOO_LARGE",error:"The request is too large."});
      for(const item of json.entries)putEntry(item.id,item.entry);
      db.lock={enabled:true,timeoutSeconds:json.timeoutSeconds,lockOnScreenLock:json.lockOnScreenLock,wrappedKey:json.wrappedKey};db.revision++;
      return send(res,200,{lock:lockView(),entries:json.entries.map(item=>db.entries.get(item.id))});}
    if(p==="/api/v1/vault"&&m==="DELETE"){ // vault reset: needs a recent Google sign-in, deletes everything incl. sessions
      if(!recentGoogle(req))return reauth(res);
      db={...freshDb(),perClient:db.perClient,revision:db.revision+1,resets:(db.resets||0)+1};return finishSessionChange(res);}
    if(p==="/api/v1/session")return send(res,200,{active:true,clientType:"web"});
    if(p==="/api/v1/bootstrap"&&m==="GET"&&!db.noBootstrap){const since=url.searchParams.get("since");const cursor=Date.now()-60000;
      const features=["encryptedLabels","atomicRotation","sessionCookie","serverSignOut","vaultRevision","deltaBootstrap","recentSignIn",...(argon2idFeature?["argon2idWrapping"]:[]),...(process.env.LIVE_CHANGES==="1"?["liveChanges"]:[])];
      if(since==null)return send(res,200,{exists:db.exists,lock:lockView(),entries:[...db.entries.values()],cursor,features,deletedIds:[],full:true});
      return send(res,200,{exists:db.exists,lock:lockView(),entries:[...db.entries.values()].filter(e=>e.updatedAtEpochMillis>Number(since)),cursor,features,
        deletedIds:[...db.tombstones].filter(([,t])=>t>Number(since)).map(([id])=>id),full:false});}
    if(p==="/api/v1/entries/changes"&&m==="GET"&&!db.noBootstrap){const since=url.searchParams.get("since");const cursor=Date.now()-60000;
      if(since==null)return send(res,200,{entries:[...db.entries.values()],deletedIds:[],cursor,full:true});
      return send(res,200,{entries:[...db.entries.values()].filter(e=>e.updatedAtEpochMillis>Number(since)),deletedIds:[...db.tombstones].filter(([,t])=>t>Number(since)).map(([id])=>id),cursor,full:false});}
    if(p==="/api/v1/account")return send(res,200,{exists:db.exists});
    if(p==="/api/v1/lock"&&m==="GET")return send(res,200,lockView());
    if(p==="/api/v1/lock"&&m==="PUT"){
      if(!db.noBootstrap){ // revision checks of current servers
        if(json.expectedRevision==null&&db.lock.wrappedKey&&json.wrappedKey&&json.wrappedKey.wrappedMasterKey!==db.lock.wrappedKey.wrappedMasterKey)return outdated(res);
        if(json.expectedRevision!=null&&json.expectedRevision!==db.revision)return conflict(res);
        if(db.lock.wrappedKey&&json.wrappedKey&&json.wrappedKey.currentVersion<db.lock.wrappedKey.currentVersion)return conflict(res,"A newer recovery key is already in use on another device. Unlock with the current passphrase and try again.");
        if(db.lock.wrappedKey&&json.wrappedKey&&json.wrappedKey.wrappedMasterKey!==db.lock.wrappedKey.wrappedMasterKey&&!recentGoogle(req))return reauth(res);
        if(json.wrappedKey&&json.wrappedKey.wrappedMasterKey!==db.lock.wrappedKey?.wrappedMasterKey)db.revision++;
      }
      db.exists=true;db.lock={enabled:true,timeoutSeconds:json.timeoutSeconds,lockOnScreenLock:json.lockOnScreenLock,wrappedKey:json.wrappedKey};return send(res,200,lockView());}
    if(p==="/api/v1/entries"&&m==="GET")return send(res,200,[...db.entries.values()]);
    if(p==="/api/v1/entries/batch"&&m==="POST"&&!db.noBootstrap){if(json.operations.some(op=>String(op.operation).trim().toUpperCase()==="DELETE")&&!recentGoogle(req))return reauth(res);let applied=0;for(const op of json.operations){
        if(op.operation==="PUT"&&db.staleNextAdd&&!db.entries.has(op.entryId)){db.staleNextAdd=false;return send(res,200,{applied,error:{status:400,message:"Your recovery key was changed on another device, so an account added with the old key could not be saved. Unlock Lockstep and add it again.",code:"STALE_KEY"}});}
        if(op.operation==="PUT"){const refused=refusal(op.entryId,op.payload);if(refused)return send(res,200,{applied,error:refused});}
        if(op.operation==="PUT")putEntry(op.entryId,op.payload);else deleteEntry(op.entryId);applied++;}return send(res,200,{applied,error:null});}
    let match=p.match(/^\/api\/v1\/entries\/([0-9a-f-]+)$/);
    if(match&&m==="PUT"&&db.staleNextAdd&&!db.entries.has(match[1])){db.staleNextAdd=false;return send(res,400,{code:"STALE_KEY",error:"Your recovery key was changed on another device, so an account added with the old key could not be saved. Unlock Lockstep and add it again."});}
    if(match&&m==="PUT"){const refused=refusal(match[1],json);if(refused)return send(res,400,{...(refused.code?{code:refused.code}:{}),error:refused.message});return send(res,200,putEntry(match[1],json));}
    if(match&&m==="DELETE"){if(!recentGoogle(req))return reauth(res);deleteEntry(match[1]);return send(res,204);}
    return send(res,m==="POST"?405:404,{error:"Not Found"});
  },LATENCY));
}).listen(API_PORT,()=>listening("api"));
