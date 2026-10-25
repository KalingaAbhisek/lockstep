const fs=require("fs"),vm=require("vm"),assert=require("node:assert/strict"),path=require("path");
(async()=>{for(const client of ["webapp","extension"]){
let decoded=0,closed=0,lastOptions;
const box={Uint8Array,DataView,createImageBitmap:async(file,options)=>{decoded++;lastOptions=options;return {width:options.resizeWidth||320,height:options.resizeHeight||240,close:()=>closed++}}};
vm.createContext(box);vm.runInContext(fs.readFileSync(process.env.IMAGE_HELPER_DIR?path.join(process.env.IMAGE_HELPER_DIR,"image-import.js"):path.join(__dirname,"../..",client,"image-import.js"),"utf8"),box);
await assert.rejects(box.LockstepImages.load({size:21*1024*1024}),/20 MB/);assert.equal(decoded,0);
const png=(width,height)=>{const bytes=new Uint8Array(45),v=new DataView(bytes.buffer);v.setUint32(0,0x89504e47);v.setUint32(8,13);bytes.set([73,72,68,82],12);bytes.set([73,69,78,68],37);v.setUint32(16,width);v.setUint32(20,height);return new Blob([bytes],{type:"image/png"});};
await assert.rejects(box.LockstepImages.load(png(10000,10000)),/40 megapixels/);assert.equal(decoded,0);
const loaded=await box.LockstepImages.load(png(3200,2400));assert.equal(lastOptions.resizeWidth,1600);assert.equal(lastOptions.resizeHeight,1200);loaded.close();assert.equal(closed,1);
box.createImageBitmap=async()=>({width:10000,height:10000,close:()=>closed++});
await assert.rejects(box.LockstepImages.load({size:100}),/40 megapixels/);assert.equal(closed,2);
console.log(client+": oversized file/dimensions rejected before decode, bounded decode requested, refused bitmap closed");
}
const {chromium}=require("playwright"),browser=await chromium.launch();
try{for(const client of ["webapp","extension"]){
 const page=await browser.newPage();await page.route("http://localhost/**",r=>r.fulfill({contentType:"text/html",body:"<!doctype html>"}));await page.goto("http://localhost/");
 for(const file of ["image-import.js","vendor/qrcode.js","vendor/jsQR.js"])await page.addScriptTag({path:file==="image-import.js"&&process.env.IMAGE_HELPER_DIR?path.join(process.env.IMAGE_HELPER_DIR,file):path.join(__dirname,"../..",client,file)});
 const qr=await page.evaluate(async()=>{
  const uri="otpauth://totp/Bounded:user?secret=JBSWY3DPEHPK3PXP&issuer=Bounded";
  const source=await QRCode.toDataURL(uri,{width:2400,margin:2});const file=await (await fetch(source)).blob();
  const loaded=await LockstepImages.load(file);
  try{const canvas=document.createElement("canvas");canvas.width=loaded.source.width;canvas.height=loaded.source.height;const ctx=canvas.getContext("2d");ctx.drawImage(loaded.source,0,0);const pixels=ctx.getImageData(0,0,canvas.width,canvas.height);return {width:canvas.width,height:canvas.height,decoded:jsQR(pixels.data,canvas.width,canvas.height)?.data===uri};}
  finally{loaded.close();}
 });
 assert.equal(qr.width,1600);assert.equal(qr.height,1600);assert(qr.decoded);
 const rotated=await page.evaluate(async()=>{
  const c=document.createElement("canvas");c.width=3200;c.height=2400;
  const original=await new Promise(resolve=>c.toBlob(resolve,"image/jpeg")),raw=new Uint8Array(await original.arrayBuffer());
  const exif=new Uint8Array([255,225,0,34,69,120,105,102,0,0,73,73,42,0,8,0,0,0,1,0,18,1,3,0,1,0,0,0,6,0,0,0,0,0,0,0]);
  const loaded=await LockstepImages.load(new Blob([raw.slice(0,2),exif,raw.slice(2)],{type:"image/jpeg"}));
  try{return [loaded.source.width,loaded.source.height]}finally{loaded.close();}
 });
 assert.deepEqual(rotated,[1200,1600]);await page.close();
 console.log(client+": actual PNG QR and rotated JPEG retain correct geometry after bounded decoding");
}}finally{await browser.close();}
})().catch(e=>{console.error(e);process.exitCode=1;});
