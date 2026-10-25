const assert = require("node:assert/strict");

// Measure browser layout work rather than relying on a timing threshold that varies across CI hosts.
module.exports = async function verifyLargeList(page, client) {
  await page.bringToFront();
  await page.waitForFunction(client=>client==="web"?!state.refreshing&&!state.localRefreshing:!refreshing&&!localRefreshing,client);
  const cdp=await page.context().newCDPSession(page);
  await cdp.send("Performance.enable");
  const metric=async()=>Object.fromEntries((await cdp.send("Performance.getMetrics")).metrics.map(m=>[m.name,m.value]));
  const before=await metric();
  try {
    const result=await page.evaluate(client=>{
      const web=client==="web", saved=web?state.entries:entries;
      window.__renderFixture={saved,refreshing:web?state.refreshing:refreshing,editing:web?state.editing:editing};
      const rows=Array.from({length:1000},(_,i)=>({...saved.find(e=>!e.error),id:crypto.randomUUID(),issuer:`Issuer ${i}`,code:"12345678",validUntilEpochMillis:Date.now()+15000,period:30}));
      if(web){state.refreshing=true;state.entries=rows;}else{refreshing=true;entries=rows;}
      const start=performance.now();renderEntries();
      return {ms:Math.round(performance.now()-start),count:document.querySelectorAll("#entries .entry").length,scale:new DOMMatrix(getComputedStyle(document.querySelector(".entry .progress")).transform).a};
    },client);
    const after=await metric();
    assert.equal(result.count,1000);
    assert.ok(after.LayoutCount-before.LayoutCount<10,`Rendering forced ${after.LayoutCount-before.LayoutCount} layouts for 1000 accounts`);
    await page.waitForFunction(scale=>new DOMMatrix(getComputedStyle(document.querySelector(".entry .progress")).transform).a<scale,result.scale,{timeout:4000});
    const later=await page.evaluate(()=>new DOMMatrix(getComputedStyle(document.querySelector(".entry .progress")).transform).a);
    assert.ok(result.scale>later && later>=0,`Countdown progress stopped animating (${result.scale} -> ${later})`);
    console.log(`[${client}] 1000 cards: ${result.ms} ms, ${after.LayoutCount-before.LayoutCount} layouts; countdown animation passed`);
    await page.emulateMedia({reducedMotion:"reduce"});
    const reduced=await page.evaluate(()=>{tick();return new DOMMatrix(getComputedStyle(document.querySelector(".entry .progress")).transform).a});
    assert.ok(reduced>0 && reduced<=1,"Reduced motion emptied the expiry bar");
    await page.waitForFunction(scale=>{tick();const value=new DOMMatrix(getComputedStyle(document.querySelector(".entry .progress")).transform).a;return value>0&&value<scale},reduced,{timeout:4000});
    await page.emulateMedia({reducedMotion:"no-preference"});
    const input=await page.evaluate(client=>{
      const web=client==="web";if(web)state.editing=true;else editing=true;
      document.body.classList.add("editing");renderEntries();
      const fields=document.querySelectorAll('#entries [data-field="issuer"]');
      fields[0].value="Edited first";fields[1].value="Other pending draft";
      const start=performance.now();for(let i=0;i<20;i++)syncDraftsFromInputs({target:fields[0]});
      const rows=web?state.entries:entries;
      const result={msPerEvent:(performance.now()-start)/20,first:rows[0].issuer,second:rows[1].issuer};
      syncDraftsFromInputs();result.afterFullScan=rows[1].issuer;return result;
    },client);
    assert.equal(input.first,"Edited first");assert.equal(input.second,"Issuer 1");assert.equal(input.afterFullScan,"Other pending draft");
    console.log(`[${client}] 1000-card edit: ${input.msPerEvent.toFixed(2)} ms per input; only the edited row updated`);
  } finally {
    await page.emulateMedia({reducedMotion:"no-preference"});
    await page.evaluate(client=>{
      const saved=window.__renderFixture;if(!saved)return;
      if(client==="web"){state.entries=saved.saved;state.refreshing=saved.refreshing;state.editing=saved.editing;}else{entries=saved.saved;refreshing=saved.refreshing;editing=saved.editing;}
      document.body.classList.toggle("editing",saved.editing);
      delete window.__renderFixture;renderEntries();
    },client);
    await cdp.detach();
  }
  await verifyExpiredCopy(page,client);
};

async function verifyExpiredCopy(page,client) {
 const fixture=await page.evaluate(client=>{
  const rows=client==="web"?state.entries:entries,entry=rows.find(e=>e.code&&!e.error);
  window.__copyFixture={entry,code:entry.code,until:entry.validUntilEpochMillis,refreshing:client==="web"?state.localRefreshing:localRefreshing,clipboard:Object.getOwnPropertyDescriptor(navigator,"clipboard")};
  if(client==="web")state.localRefreshing=true;else localRefreshing=true;
  entry.code="EXPIRED";entry.validUntilEpochMillis=Date.now()-1000;window.__copied=null;
  Object.defineProperty(navigator,"clipboard",{configurable:true,value:{writeText:async text=>window.__copied=text}});renderEntries();return entry.id;
 },client);
 try {
  await page.click(`#entries .entry[data-id="${fixture}"] [data-action="copy"]`);
  await page.waitForFunction(()=>/^\d{6,8}$/.test(window.__copied));
 } finally {
  await page.evaluate(client=>{const saved=window.__copyFixture;saved.entry.code=saved.code;saved.entry.validUntilEpochMillis=saved.until;
   if(client==="web")state.localRefreshing=saved.refreshing;else localRefreshing=saved.refreshing;
   if(saved.clipboard)Object.defineProperty(navigator,"clipboard",saved.clipboard);else delete navigator.clipboard;
   delete window.__copyFixture;delete window.__copied;renderEntries();},client);
 }
 console.log(`[${client}] expired code regenerated before copying`);
}

module.exports.verifyLongConfirmation=async(page,client)=>{
  const viewport=page.viewportSize();
  if(client==="web")await page.setViewportSize({width:320,height:568});
  await page.evaluate(()=>{void confirmAction({title:"Remove account?",message:"A".repeat(128)+" ("+"B".repeat(256)+") will be removed.",label:"Remove",confirmLabel:"Remove",passphrase:true})});
  await page.waitForSelector("#confirm-dialog[open]");await page.waitForTimeout(300);
  const layout=await page.$eval("#confirm-dialog",dialog=>{
    const button=document.getElementById("confirm-accept").getBoundingClientRect();
    return {fits:dialog.scrollWidth<=dialog.clientWidth,buttonVisible:button.left>=0&&button.right<=innerWidth};
  });
  assert.ok(layout.fits&&layout.buttonVisible,"Long labels overflowed the confirmation dialog");
  await page.click("#confirm-cancel");
  if(client==="web")await page.setViewportSize(viewport);
};
