// One web session and one extension session per Google account (like the real API: one slot per client type).
// Signing in to another web app replaces only the web session, and another extension only the extension session.
// The replaced client is signed out at once (live notification), clears its unlocked key, and the other client
// keeps working. Two simultaneous sign-ins leave exactly one valid session.
const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
const P = "session-test-passphrase";
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = () => `${b64({alg:"RS256"})}.${b64({sub:"user-1",name:"Sessions",email:"s@example.test",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const uri = (name, secret) => `otpauth://totp/${name}:s?secret=${secret}&issuer=${name}`;
const log = (...values) => console.log(`[${label}]`, ...values);
const control = q => fetch(`${API}/__control?${q}`).then(r => r.json());
const googleStub = "window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};";
const view = page => page.evaluate(() => ["signed-out", "signed-in", "locked", "restore"].find(id => !document.getElementById(id).classList.contains("hidden")) || "loading");
(async () => {
 await control("reset=1"); await control("perClientSessions=1");
 const context = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-sessions-${Date.now()}`), {
  channel:"chromium", headless:true, ignoreDefaultArgs:["--disable-extensions"],
  args:["--headless=new", `--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`] });
 const otherBrowser = await chromium.launch(); // a second device: its own browser and storage
 try {
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:googleStub }));
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const extensionId = worker.url().split("/")[2];
  const errors = [];
  // Web app A: sign in, protect the vault, add accounts.
  const webA = await context.newPage(); webA.on("pageerror", e => errors.push(`webA: ${e.message}`));
  await webA.goto(WEB); await webA.waitForTimeout(500);
  await webA.evaluate(t => onGoogleCredential({ credential: t }), token());
  await webA.waitForSelector("#lock-dialog[open]");
  await webA.fill("#lock-passcode", P); await webA.fill("#lock-confirm", P); await webA.click('#lock-form button[type="submit"]');
  await webA.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await webA.evaluate(us => importUris(us), [uri("Alpha", "JBSWY3DPEHPK3PXP"), uri("Bravo", "GEZDGNBVGY3TQOJQ")]);
  // Extension: a real extension sign-in (its own session slot), unlocked with the vault passphrase.
  await worker.evaluate(async ({ t, P }) => {
   await chrome.storage.local.set({ vaultSubject:"user-1", vaultDisplayName:"Sessions" });
   await chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() });
   await registerAppSession(); await getLockConfig(); await verifyLock(P); await synchronize();
  }, { t: token(), P });
  const popup = await context.newPage(); popup.on("pageerror", e => errors.push(`popup: ${e.message}`));
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  await popup.waitForSelector("#entries .entry:not(.entry-skel)");
  let state = await control("");
  assert(state.sessions.web && state.sessions.extension && state.sessions.web !== state.sessions.extension, "web and extension need their own sessions");
  for (const started = Date.now(); (await control("")).liveConnections < 2;) { if (Date.now() - started > 10000) throw Error("live channels did not connect"); await webA.waitForTimeout(100); }
  log("web app A and the extension are signed in with separate sessions");

  // 1. Web app B (another device) signs in: only web app A is signed out, at once; the extension keeps working.
  const deviceB = await otherBrowser.newContext(); await deviceB.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:googleStub }));
  const webB = await deviceB.newPage(); webB.on("pageerror", e => errors.push(`webB: ${e.message}`));
  await webB.goto(WEB); await webB.waitForTimeout(500);
  const replacedAt = Date.now();
  await webB.evaluate(t => onGoogleCredential({ credential: t }), token());
  await webA.waitForSelector("#signed-out:not(.hidden)", { timeout: 3000 });
  const latency = Date.now() - replacedAt;
  const aState = await webA.evaluate(() => ({ unlocked: LockstepVault.isUnlocked("user-1"), rows: document.querySelectorAll("#entries .entry").length,
   sessionKey: Object.keys(sessionStorage).some(k => k.startsWith("authsync.session-key.")), toast: document.getElementById("toast").textContent }));
  assert.equal(aState.unlocked, false, "the replaced web app kept its unlocked key");
  assert.equal(aState.rows, 0, "the replaced web app still shows codes");
  assert.equal(aState.sessionKey, false, "the replaced web app kept its saved unlocked session");
  assert.match(aState.toast, /replaced by a login on another device|ended on another device/);
  assert.notEqual(await view(webB), "signed-out", "web app B was not signed in");
  assert.equal(await worker.evaluate(async () => { await api("/api/v1/session"); return LockstepVault.isUnlocked("user-1"); }), true, "the extension was affected by a web sign-in");
  await popup.waitForTimeout(500); assert.equal(await popup.evaluate(() => isAuthenticated), true, "the extension popup was signed out by a web sign-in");
  log(`second web app sign-in signed out the first in ${latency} ms (keys cleared); the extension kept working`);

  // 2. Another extension install signs in: only this extension is signed out, at once; web app B keeps working.
  const before = Date.now();
  const other = await fetch(`${API}/api/v1/session`, { method:"POST", headers:{ Authorization:`Bearer ${token()}`, "X-Lockstep-Client":"extension" } });
  assert.equal(other.status, 200);
  await popup.waitForSelector("#signed-out:not(.hidden)", { timeout: 3000 });
  assert.equal(await worker.evaluate(() => LockstepVault.isUnlocked("user-1")), false, "the replaced extension kept its unlocked key");
  assert.equal(await worker.evaluate(async () => Boolean((await chrome.storage.session.get("unlockedMaster")).unlockedMaster)), false, "the replaced extension kept its saved key");
  assert.equal(await webB.evaluate(() => api("/api/v1/session").then(() => true, () => false)), true, "web app B was signed out by an extension sign-in");
  log(`second extension sign-in signed out the first in ${Date.now() - before} ms (keys cleared); the web app kept working`);

  // 3. Two web apps sign in at the same moment: exactly one session is valid, and the other web app is signed out.
  await webA.evaluate(() => { document.getElementById("toast").textContent = ""; });
  await Promise.all([webA.evaluate(t => onGoogleCredential({ credential: t }), token()), webB.evaluate(t => onGoogleCredential({ credential: t }), token())]);
  await webA.waitForTimeout(3000);
  const views = { A: await view(webA), B: await view(webB) };
  const valid = { A: await webA.evaluate(() => api("/api/v1/session").then(() => true, () => false)), B: await webB.evaluate(() => api("/api/v1/session").then(() => true, () => false)) };
  await webA.waitForTimeout(500);
  const finalViews = { A: await view(webA), B: await view(webB) };
  assert.equal(Number(valid.A) + Number(valid.B), 1, `exactly one web session must stay valid: ${JSON.stringify(valid)}`);
  assert.equal([finalViews.A, finalViews.B].filter(v => v === "signed-out").length, 1, `exactly one web app must end signed out: ${JSON.stringify(finalViews)}`);
  log(`simultaneous web sign-ins: ${valid.A ? "A" : "B"} kept the session, the other was signed out (${JSON.stringify(views)} -> ${JSON.stringify(finalViews)})`);
  assert.deepEqual(errors, []);
 } finally { await context.close(); await otherBrowser.close(); }
})().catch(error => { console.error(`[${label}] FAILED`, error); process.exitCode = 1; });
