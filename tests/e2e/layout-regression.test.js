// Render the actual card builders, HTML and final CSS cascade without credentials or a live API.
const fs=require("node:fs"),path=require("node:path"),os=require("node:os"),assert=require("node:assert/strict"),{chromium}=require("playwright");
const root=path.resolve(__dirname,"../.."),screens=fs.mkdtempSync(path.join(os.tmpdir(),"lockstep-layout-"));
function fn(source,name){const start=source.indexOf("function "+name+"("),match=/\)\s*\{/.exec(source.slice(start));let depth=0;
 for(let i=start+match.index+match[0].length-1;i<source.length;i++){if(source[i]==="{")depth++;if(source[i]==="}"&&!--depth)return source.slice(start,i+1);}throw Error("Missing function "+name);}
(async()=>{const browser=await chromium.launch();try{for(const client of ["webapp","extension"]){
 const ext=client==="extension",context=await browser.newContext(),page=await context.newPage();
 const html=fs.readFileSync(path.join(root,client,ext?"popup.html":"index.html"),"utf8").replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi,"");
 await page.route("http://layout.test/**",route=>{const pathname=new URL(route.request().url()).pathname,css=pathname.endsWith(".css");
  if(/^\/icons\/[a-zA-Z0-9-]+\.png$/.test(pathname))return route.fulfill({contentType:"image/png",body:fs.readFileSync(path.join(root,client,pathname.slice(1)))});
  if(/^\/icons\/[a-zA-Z0-9-]+\.svg$/.test(pathname))return route.fulfill({contentType:"image/svg+xml",body:fs.readFileSync(path.join(root,client,pathname.slice(1)),"utf8")});
  return route.fulfill({contentType:css?"text/css":"text/html",body:css?fs.readFileSync(path.join(root,client,ext?"popup.css":"styles.css"),"utf8"):html});});
 await page.goto("http://layout.test/");
 const source=fs.readFileSync(path.join(root,client,ext?"popup.js":"app.js"),"utf8");
 await page.addScriptTag({content:["h","iconNode","formatCode","renderEntries"].map(name=>fn(source,name)).join("\n")});
 await page.evaluate(()=>{
  globalThis.el=globalThis.$=id=>document.getElementById(id);globalThis.tick=globalThis.updateAccountSummary=()=>{};
  globalThis.entries=[{id:"fixture",issuer:"LongIssuerWithoutSpaces".repeat(6),accountName:"long.account.name".repeat(14),code:"12345678",periodSeconds:30,localOnly:true,canRetry:true,needsOldPassphrase:true,pinned:true}];
  globalThis.editing=false;globalThis.state={entries,editing:false};
  for(const id of ["signed-out","locked","restore","app-loading","initializing"])document.getElementById(id)?.classList.add("hidden");
  for(const id of ["signed-in","auth-view"])document.getElementById(id)?.classList.remove("hidden");
  renderEntries();
 });
 const sizes=ext?[[380,600],[380,360]]:[[320,568],[390,844],[768,1024],[1440,900],[320,360]];
 for(const theme of ["light","dark"])for(const [width,height]of sizes){
  await page.setViewportSize({width,height});await page.evaluate(t=>document.documentElement.dataset.theme=t,theme);
  await page.waitForTimeout(350); // Let the actual theme transition settle before measuring or capturing.
  const issues=await page.evaluate(()=>{
   const problems=[];if(document.documentElement.scrollWidth>innerWidth+1)problems.push("horizontal page overflow");
   const card=document.querySelector(".entry"),bounds=card.getBoundingClientRect();
   for(const button of card.querySelectorAll(".entry-actions button,.card-actions button")){const r=button.getBoundingClientRect();if(r.left<bounds.left||r.right>bounds.right+1)problems.push("action outside card");}
   return problems;
  });assert.deepEqual(issues,[],`${client} ${theme} ${width}x${height}`);
  if(width===sizes[0][0]&&height===sizes[0][1])await page.screenshot({path:path.join(screens,`${client}-${theme}.png`),fullPage:true});
  await page.evaluate(()=>document.getElementById("manual-dialog").showModal());
  const dialog=await page.$eval("#manual-dialog",d=>({width:d.getBoundingClientRect().width,height:d.getBoundingClientRect().height,screenWidth:innerWidth,screenHeight:innerHeight}));
  assert(dialog.width<=dialog.screenWidth+1&&dialog.height<=dialog.screenHeight+1,`${client}: manual dialog exceeds viewport`);
  await page.evaluate(()=>document.getElementById("manual-dialog").close());
 }
 await context.close();console.log(`${client}: long labels, four actions, light/dark themes and short-screen dialogs fit`);
}}finally{await browser.close()}console.log("Layout screenshots: "+screens);})().catch(error=>{console.error(error);process.exitCode=1});
