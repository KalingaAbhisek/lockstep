const fs=require("node:fs"),path=require("node:path"),vm=require("node:vm"),assert=require("node:assert/strict");
const source=fs.readFileSync(path.resolve(__dirname,"../../webapp/live-changes.js"),"utf8");
const box={AbortController,TextDecoder,setTimeout,clearTimeout};vm.createContext(box);vm.runInContext(source,box);
const wait=ms=>new Promise(resolve=>setTimeout(resolve,ms));
async function until(check){for(let i=0;i<200;i++){if(check())return;await wait(10)}throw Error("Live test timed out")}
(async()=>{
 let stream,updates=0,release,entered;
 const ready=new Promise(resolve=>entered=resolve),held=new Promise(resolve=>release=resolve);
 const channel=box.LockstepLiveChanges.watch({
  connect:async signal=>new Response(new ReadableStream({start(controller){stream=controller;signal.addEventListener("abort",()=>controller.close(),{once:true})}}),{headers:{"Content-Type":"text/event-stream"}}),
  onChange:async()=>{updates++;if(updates===1){entered();await held;}}
 });
 await until(()=>stream);
 for(const chunk of ["ev","ent: change\r","\ndata: {}\r\n\r\n"])stream.enqueue(new TextEncoder().encode(chunk));
 await ready;
 for(let i=0;i<20;i++)stream.enqueue(new TextEncoder().encode("event: change\ndata: {}\n\n"));
 await wait(30);release();await until(()=>updates===2);await wait(50);assert.equal(updates,2,"events arriving during sync must coalesce into a follow-up");
 stream.enqueue(new TextEncoder().encode(": keepalive\n\n"));await wait(30);assert.equal(updates,2);
 channel.stop();await channel.finished;
 let attempts=0;
 const refused=box.LockstepLiveChanges.watch({connect:async()=>{attempts++;return new Response("limited",{status:429,headers:{"Retry-After":"2"}})},onChange:async()=>{}});
 await wait(100);assert.equal(attempts,1,"Retry-After must stop an immediate reconnect loop");refused.stop();await refused.finished;
 let malformedAttempts=0;
 const malformed=box.LockstepLiveChanges.watch({connect:async()=>{malformedAttempts++;return new Response("limited",{status:429,headers:{"Retry-After":"not-a-date"}})},onChange:async()=>{}});
 await wait(100);assert.equal(malformedAttempts,1,"a malformed Retry-After must not cause a reconnect spin");malformed.stop();await malformed.finished;
 let retries=0,secondStream;
 const retrying=box.LockstepLiveChanges.watch({
  connect:async signal=>new Response(new ReadableStream({start(controller){secondStream=controller;signal.addEventListener("abort",()=>controller.close(),{once:true})}}),{headers:{"Content-Type":"text/event-stream"}}),
  onChange:async()=>{if(++retries===1)throw Error("Local rotation in progress");}
 });
 await until(()=>secondStream);secondStream.enqueue(new TextEncoder().encode("event: change\ndata: {}\n\n"));await until(()=>retries===2);
 retrying.stop();await retrying.finished;
 let sessionStream,ended=0,ordinary=0;
 const revoked=box.LockstepLiveChanges.watch({
  connect:async signal=>new Response(new ReadableStream({start(controller){sessionStream=controller;signal.addEventListener("abort",()=>controller.close(),{once:true})}}),{headers:{"Content-Type":"text/event-stream"}}),
  onChange:async()=>ordinary++,onSession:async()=>ended++
 });
 await until(()=>sessionStream);sessionStream.enqueue(new TextEncoder().encode("event: session\ndata: {}\n\n"));await revoked.finished;await until(()=>ended===1);
 assert.equal(ordinary,0,"session revocation must not wait for cached ordinary reads");
 console.log("Live channel: split SSE frames, coalescing, heartbeat filtering, cancellation, Retry-After and busy-sync retry passed");
})().catch(error=>{console.error(error);process.exitCode=1});
