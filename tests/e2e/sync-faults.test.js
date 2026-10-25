const fs=require("fs"),vm=require("vm"),assert=require("node:assert/strict");
function section(s,a,b){return s.slice(s.indexOf(a),s.indexOf(b,s.indexOf(a)));}
(async()=>{
for(const ext of [false,true]){
 const s=fs.readFileSync(require("path").join(__dirname,"../..",ext?"extension/service-worker.js":"webapp/app.js"),"utf8");
 let identity={owner:"A",subject:"A",generation:1,session:"one"},sent=0;
 const sandbox={authenticationGeneration:1,authenticationSnapshot:()=>ext?Promise.resolve({...identity}):({...identity}),
 assertSyncCooldown:()=>{},state:{subject:"A",vaultRequests:{signal:{aborted:false}}},subject:async()=>identity.owner,
 api:async(path,opts)=>{assert.deepEqual(opts.expectedAuthentication,identity);sent++;return {};}};
 vm.createContext(sandbox);
 vm.runInContext(section(s,ext?"function transport(owner)":"function vaultTransport(owner)",ext?"// Set while this device":"// A change the server refused"),sandbox);
 const t=sandbox[ext?"transport":"vaultTransport"]("A");await t.put("id",{});assert.equal(sent,1);
 // The actual API checks the captured authentication; this stub rejects mismatched snapshots.
 identity={...identity,owner:"B",subject:"B",generation:2};sandbox.authenticationGeneration=2;
 await assert.rejects(t.put("id",{}));assert.equal(sent,1);
 vm.runInContext(section(s,"const syncRetryStates","async function apiRequest("),sandbox);
 sandbox.apiRequest=async()=>{throw Object.assign(new Error("stalled body"),{name:"TimeoutError"});};
 await assert.rejects(sandbox.api("/test"),e=>e.code==="BACKEND_UNAVAILABLE"&&e.message.includes("may still"));
 // Transient failures are retried every 5 to 10 seconds, however often they repeat (no growing backoff).
 { const first=sandbox.retryDelay(ext?"B":"A");assert(first>=4900&&first<=10000,`transient retry after ${first} ms`);
   for(let i=0;i<8;i++)sandbox.recordSyncFailure("D",{});
   const repeated=sandbox.retryDelay("D");assert(repeated>=4900&&repeated<=10000,`retry after 9 failures: ${repeated} ms`); }
 const serverDelay=sandbox.retryAfterMillis({headers:{get:()=>"60"}});assert.equal(serverDelay,60000);
 sandbox.recordSyncFailure("C",{retryAfterMillis:serverDelay});assert(sandbox.retryDelay("C")>=59000);
 sandbox.recordSyncFailure("C",{});assert(sandbox.retryDelay("C")>=59000);
 sandbox.resetNetworkBackoff();assert(sandbox.retryDelay("C")>=59000);assert.equal(sandbox.retryDelay(ext?"B":"A"),0);
 sandbox.apiRequest=async()=>{throw Object.assign(new Error("Request limit"),{status:429,code:"RATE_LIMITED",retryAfterMillis:60000});};
 await assert.rejects(sandbox.api("/test"));assert(sandbox.retryDelay(ext?"B":"A")>=59000);
 console.log((ext?"extension":"webapp")+": account-bound transport, timeout normalization and retry delays passed");
}
})().catch(e=>{console.error(e);process.exitCode=1;});
