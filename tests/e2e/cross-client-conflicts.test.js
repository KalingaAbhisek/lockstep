// The web app and the extension (same Google account) change the same vault at the same moment. After every race,
// the server, the web app and the extension must hold exactly the same accounts (IDs, versions and names), with
// nothing left queued, nothing lost and nothing undecryptable. Changes reach the other client through the live
// channel only: the 30-second timer and focus refreshes are switched off in this fixture.
const { chromium } = require("playwright");
const assert = require("node:assert/strict"), path = require("node:path"), os = require("node:os");
const [label, extensionDir] = process.argv.slice(2);
const API = `http://localhost:${process.env.API_PORT}`;
const WEB = `http://localhost:${process.env.WEB_PORT}/lockstep/`;
const owner = "user-1";
let P = "conflict-passphrase-1";
const b64 = value => Buffer.from(JSON.stringify(value)).toString("base64url");
const token = () => `${b64({alg:"RS256"})}.${b64({sub:owner,name:"Race",email:"race@example.test",iat:Math.floor(Date.now()/1000),exp:Math.floor(Date.now()/1000)+3600})}.sig`;
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const uri = (name, n) => `otpauth://totp/${encodeURIComponent(name)}:race?secret=${Array.from({length:16},(_, i)=>B32[(n*5+i*7)%32]).join("")}&issuer=${encodeURIComponent(name)}`;
const log = (...values) => console.log(`[${label}]`, ...values);
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
 await fetch(`${API}/__control?reset=1`);
 const context = await chromium.launchPersistentContext(path.join(os.tmpdir(), `lockstep-conflicts-${Date.now()}`), {
  channel:"chromium", headless:true, ignoreDefaultArgs:["--disable-extensions"],
  args:["--headless=new", `--disable-extensions-except=${extensionDir}`, `--load-extension=${extensionDir}`] });
 try {
  await context.addInitScript(() => {
   const interval = window.setInterval.bind(window);
   window.setInterval = (fn, ms, ...args) => ms === 30000 ? 0 : interval(fn, ms, ...args);
   const windowListener = window.addEventListener.bind(window), documentListener = document.addEventListener.bind(document);
   window.addEventListener = (name, ...args) => { if (name !== "focus") windowListener(name, ...args); };
   document.addEventListener = (name, ...args) => { if (name !== "visibilitychange") documentListener(name, ...args); };
  });
  await context.route("https://accounts.google.com/**", r => r.fulfill({ contentType:"application/javascript", body:"window.google={accounts:{id:{initialize(){},renderButton(){},disableAutoSelect(){},prompt(){}}}};" }));
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  const extensionId = worker.url().split("/")[2];
  const errors = [];
  const web = await context.newPage(); web.on("pageerror", e => errors.push(`web: ${e.message}`));
  await web.goto(WEB); await web.waitForTimeout(600);
  await web.evaluate(t => onGoogleCredential({ credential: t }), token());
  await web.waitForSelector("#lock-dialog[open]");
  await web.fill("#lock-passcode", P); await web.fill("#lock-confirm", P); await web.click('#lock-form button[type="submit"]');
  await web.waitForFunction(() => !document.getElementById("lock-dialog").open);
  await web.evaluate(us => importUris(us), [uri("Alpha", 1), uri("Bravo", 2), uri("Charlie", 3)]);
  await worker.evaluate(async ({ t, P }) => {
   await chrome.storage.local.set({ vaultSubject:"user-1", vaultDisplayName:"Race", appSessionId:"session-token", appSessionExpiry:Date.now()+864e5 });
   await chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() });
   await getLockConfig(); await verifyLock(P); await synchronize();
  }, { t: token(), P });
  const popup = await context.newPage(); popup.on("pageerror", e => errors.push(`popup: ${e.message}`));
  await popup.goto(`chrome-extension://${extensionId}/popup.html`);
  await popup.waitForSelector("#entries .entry:not(.entry-skel)");
  for (const started = Date.now(); (await fetch(`${API}/__control`).then(r => r.json())).liveConnections < 2;) {
   if (Date.now() - started > 10000) throw Error("live channels did not connect"); await sleep(100);
  }

  // Waits until server, web app and extension agree exactly, without asking either client to sync.
  async function converged(step, timeout = 10000) {
   let last;
   for (const started = Date.now(); Date.now() - started < timeout; await sleep(250)) {
    const server = (await web.evaluate(() => api("/api/v1/entries").catch(() => null)) || []).map(e => `${e.id}:${e.mutationId}`).sort();
    const webState = await web.evaluate(async () => ({ rows: (await LockstepVault.localEncryptedEntries("user-1")).map(e => `${e.id}:${e.mutationId}`).sort(),
     pending: await LockstepVault.pendingCount("user-1"),
     names: LockstepVault.isUnlocked("user-1") ? (await LockstepVault.listEntries("user-1")).map(e => e.error ? `!${e.issuer}` : e.issuer).sort() : null }));
    const extState = await worker.evaluate(async () => ({ rows: (await LockstepVault.localEncryptedEntries("user-1")).map(e => `${e.id}:${e.mutationId}`).sort(),
     pending: await LockstepVault.pendingCount("user-1"),
     names: LockstepVault.isUnlocked("user-1") ? (await LockstepVault.listEntries("user-1")).map(e => e.error ? `!${e.issuer}` : e.issuer).sort() : null }));
    last = { server: server.length, web: webState, ext: extState };
    const same = JSON.stringify(server) === JSON.stringify(webState.rows) && JSON.stringify(server) === JSON.stringify(extState.rows)
     && webState.pending === 0 && extState.pending === 0
     && (!webState.names || !extState.names || JSON.stringify(webState.names) === JSON.stringify(extState.names));
    if (same) {
     const names = webState.names || extState.names || [];
     assert(!names.some(n => n.startsWith("!")), `${step}: an account cannot be opened: ${names}`);
     return names;
    }
   }
   throw Error(`${step}: clients did not converge: ${JSON.stringify(last).slice(0, 1500)}`);
  }
  const find = (page, issuer) => page.evaluate(async issuer => (await LockstepVault.listEntries("user-1")).find(e => e.issuer === issuer)?.id, issuer);
  await converged("setup");

  // 1. Both clients rename the same account at the same moment: one rename wins everywhere, nothing is duplicated.
  const alpha = await find(web, "Alpha");
  await Promise.all([
   web.evaluate(async id => { await LockstepVault.updateEntry("user-1", id, "Alpha from web", "race"); await syncVault().catch(() => null); }, alpha),
   worker.evaluate(async id => updateEntry(id, "Alpha from extension", "race").catch(() => null), alpha)
  ]);
  let names = await converged("simultaneous rename");
  const winners = names.filter(n => n.startsWith("Alpha"));
  assert.equal(winners.length, 1, `the renamed account must exist exactly once: ${names}`);
  log("simultaneous rename: one version kept everywhere:", winners[0]);

  // 2. Rename in the web app while the extension deletes the same account: the deletion wins everywhere.
  const bravo = await find(web, "Bravo");
  await Promise.all([
   web.evaluate(async id => { await LockstepVault.updateEntry("user-1", id, "Bravo renamed", "race"); await syncVault().catch(() => null); }, bravo),
   worker.evaluate(async ({ id, P }) => deleteEntry(id, P), { id: bravo, P })
  ]);
  names = await converged("rename against delete");
  assert(!names.some(n => n.startsWith("Bravo")), `a deleted account came back: ${names}`);
  log("rename against delete: deletion kept on every client");

  // 3. Both clients add ten accounts at the same time: all twenty arrive everywhere, once each.
  await Promise.all([
   web.evaluate(us => importUris(us), Array.from({ length: 10 }, (_, i) => uri(`Web ${i}`, 10 + i))),
   worker.evaluate(us => importEntries(us), Array.from({ length: 10 }, (_, i) => uri(`Ext ${i}`, 40 + i)))
  ]);
  names = await converged("simultaneous additions", 20000);
  assert.equal(names.filter(n => /^(Web|Ext) \d$/.test(n)).length, 20, `simultaneous additions were lost or duplicated: ${names}`);
  log("simultaneous additions: all 20 present once on server, web app and extension");
  const countBefore = names.length;

  // 4. Both clients change the passphrase at the same moment: exactly one passphrase wins; the other client
  //    takes the winning key (it never overwrites it), and both open every account with it afterwards.
  const fromWeb = "conflict-passphrase-web", fromExt = "conflict-passphrase-ext";
  await web.evaluate(t => { state.token = t; }, token());
  await worker.evaluate(async t => chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() }), token());
  await web.click("#open-settings"); await web.click("#settings-lock");
  await web.fill("#lock-passcode", fromWeb); await web.fill("#lock-confirm", fromWeb);
  await Promise.all([
   web.click('#lock-form button[type="submit"]'),
   worker.evaluate(P => setLockConfig(P, 300, false, false).then(() => "saved", e => e.code || e.message), fromExt)
  ]);
  await sleep(2500);
  const unlockWith = async P => {
   const webOk = await web.evaluate(async P => { if (LockstepVault.isUnlocked("user-1")) return "already"; return LockstepVault.checkPassphrase("user-1", P); }, P);
   const extOk = await worker.evaluate(async P => LockstepVault.checkPassphrase("user-1", P), P);
   return { webOk, extOk };
  };
  const a = await unlockWith(fromWeb), b = await unlockWith(fromExt);
  const winner = (a.extOk === true && a.webOk !== false) ? fromWeb : (b.extOk === true && b.webOk !== false) ? fromExt : null;
  assert(winner, `neither passphrase opens both clients: web-pass ${JSON.stringify(a)}, ext-pass ${JSON.stringify(b)}`);
  assert(!((a.extOk === true && a.webOk === true) && (b.extOk === true && b.webOk === true)), "both passphrases cannot be valid at once");
  P = winner;
  if (!await web.evaluate(() => LockstepVault.isUnlocked("user-1"))) {
   await web.waitForSelector("#locked:not(.hidden)");
   await web.fill("#unlock-passcode", P); await web.click('#unlock-form button[type="submit"]');
   await web.waitForSelector("#signed-in:not(.hidden)");
  }
  await worker.evaluate(async P => { if (!LockstepVault.isUnlocked("user-1")) await verifyLock(P); }, P);
  names = await converged("simultaneous passphrase change");
  assert.equal(names.length, countBefore, "accounts were lost by a passphrase race");
  log(`simultaneous passphrase change: "${winner === fromWeb ? "web app" : "extension"}" won; both clients open all ${names.length} accounts with it`);

  // 4b. The same race with the extension a moment later, so the web app's change reaches the server first and the
  //     extension is the one that must take the other key.
  {
   const fromWeb2 = "conflict-passphrase-web-2", fromExt2 = "conflict-passphrase-ext-2";
   await web.evaluate(t => { state.token = t; }, token());
   await worker.evaluate(async t => chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() }), token());
   await web.click("#open-settings"); await web.click("#settings-lock");
   await web.fill("#lock-passcode", fromWeb2); await web.fill("#lock-confirm", fromWeb2);
   const [, extOutcome] = await Promise.all([
    web.click('#lock-form button[type="submit"]'),
    worker.evaluate(async P => { await new Promise(r => setTimeout(r, 2500)); return setLockConfig(P, 300, false, false).then(() => "saved", e => e.code || e.message); }, fromExt2)
   ]);
   await sleep(2000);
   const webOpens = await worker.evaluate(P => LockstepVault.checkPassphrase("user-1", P), fromWeb2);
   const extOpens = await worker.evaluate(P => LockstepVault.checkPassphrase("user-1", P), fromExt2);
   assert.notEqual(webOpens, extOpens, `exactly one passphrase must be valid (web ${webOpens}, extension ${extOpens}, extension result ${extOutcome})`);
   P = webOpens ? fromWeb2 : fromExt2;
   // The extension, locked by the web app's change before it saved its own, reports the usual "locked" result.
   if (webOpens) assert(["VAULT_LOCKED", "saved"].includes(extOutcome) || /locked|changed on another device/i.test(extOutcome), `unexpected extension result: ${extOutcome}`);
   if (!await web.evaluate(() => LockstepVault.isUnlocked("user-1"))) {
    await web.waitForSelector("#locked:not(.hidden)");
    await web.fill("#unlock-passcode", P); await web.click('#unlock-form button[type="submit"]'); await web.waitForSelector("#signed-in:not(.hidden)");
   }
   await worker.evaluate(async P => { if (!LockstepVault.isUnlocked("user-1")) await verifyLock(P); }, P);
   names = await converged("passphrase change, extension later");
   assert.equal(names.length, countBefore, "accounts were lost by a passphrase race");
   log(`passphrase change with the extension later: "${P === fromWeb2 ? "web app" : "extension"}" won (extension: ${extOutcome}); all ${names.length} accounts open on both`);
  }

  // 5. Recovery-key rotation in the web app while the extension adds an account: whatever the order, every account
  //    ends up on the server under the new key and opens on both clients.
  await web.evaluate(t => { state.token = t; }, token());
  await web.click("#open-settings"); await web.click("#settings-key-rotate");
  await web.waitForSelector("#confirm-dialog[open]"); await web.fill("#confirm-passkey", P);
  await Promise.all([
   web.click("#confirm-accept"),
   worker.evaluate(u => addOtpUri(u).catch(e => e.code || e.message), uri("During rotation", 90))
  ]);
  await web.waitForFunction(() => /rotated to version|could not|changed|try again/i.test(document.getElementById("toast").textContent), null, { timeout: 30000 });
  const rotationOutcome = await web.textContent("#toast");
  // The extension locks if the rotation won; unlocking re-encrypts an account it added with the old key.
  await sleep(1500);
  await worker.evaluate(async P => { if (!LockstepVault.isUnlocked("user-1")) await verifyLock(P); await synchronize().catch(() => null); }, P);
  if (!await web.evaluate(() => LockstepVault.isUnlocked("user-1"))) {
   await web.fill("#unlock-passcode", P); await web.click('#unlock-form button[type="submit"]'); await web.waitForSelector("#signed-in:not(.hidden)");
  }
  names = await converged("rotation against addition", 20000);
  assert(names.includes("During rotation"), `the account added during the rotation was lost: ${names}`);
  const versions = await web.evaluate(async () => ({ key: (await LockstepVault.exportWrappedKey("user-1")).currentVersion,
   entries: [...new Set((await api("/api/v1/entries")).map(e => e.keyVersion))] }));
  assert(versions.entries.length === 1 && versions.entries[0] === versions.key, `server accounts use mixed key versions: ${JSON.stringify(versions)}`);
  log(`rotation against addition (${rotationOutcome.trim().slice(0, 60)}…): all ${names.length} accounts on key version ${versions.key} everywhere`);

  // 6. Both clients rotate the recovery key at the same moment: exactly one rotation is applied; the other is refused
  //    without changing anything, and every account ends up under one key version that both clients open.
  await web.evaluate(t => { state.token = t; }, token());
  await worker.evaluate(async t => chrome.storage.session.set({ idToken:t, tokenExpiry:Date.now()+3600e3, interactiveSignInAt:Date.now() }), token());
  const versionBefore = (await fetch(`${API}/__control`).then(r => r.json())).keyVersion;
  await web.evaluate(() => clearToast());
  await web.click("#open-settings"); await web.click("#settings-key-rotate");
  await web.waitForSelector("#confirm-dialog[open]"); await web.fill("#confirm-passkey", P);
  const [, extRotation] = await Promise.all([
   // If the extension's rotation lands first, the web app locks and its question closes before the click: that
   // is one of the expected outcomes (checked below), so the click does not wait for a dialog that is gone.
   web.click("#confirm-accept", { timeout: 5000 }).catch(() => null),
   worker.evaluate(P => rotateEncryptionKey(P).then(r => `rotated to ${r.version}`, e => e.code || e.message), P)
  ]);
  // The web app either rotated, was refused, or was locked by the extension's rotation before it started.
  await web.waitForFunction(() => /rotated to version|changed|try again|could not/i.test(document.getElementById("toast").textContent) || !document.getElementById("locked").classList.contains("hidden"), null, { timeout: 30000 });
  const webRotation = (await web.textContent("#toast")).trim();
  await sleep(1500);
  const versionAfter = (await fetch(`${API}/__control`).then(r => r.json())).keyVersion;
  assert.equal(versionAfter, versionBefore + 1, `exactly one rotation must apply (key ${versionBefore} -> ${versionAfter})`);
  if (!await web.evaluate(() => LockstepVault.isUnlocked("user-1"))) {
   await web.waitForSelector("#locked:not(.hidden)");
   assert.equal(await web.evaluate(() => document.querySelector("dialog[open]")?.id ?? null), null, "a dialog covers the lock screen");
   await web.fill("#unlock-passcode", P); await web.click('#unlock-form button[type="submit"]'); await web.waitForSelector("#signed-in:not(.hidden)");
  }
  await worker.evaluate(async P => { if (!LockstepVault.isUnlocked("user-1")) await verifyLock(P); await synchronize().catch(() => null); }, P);
  const countRotations = names.length;
  names = await converged("simultaneous rotations", 20000);
  assert.equal(names.length, countRotations, "accounts were lost by simultaneous rotations");
  const keys = await web.evaluate(async () => [...new Set((await api("/api/v1/entries")).map(e => e.keyVersion))]);
  assert.deepEqual(keys, [versionAfter], `server accounts use mixed key versions after simultaneous rotations: ${keys}`);
  log(`simultaneous rotations: one applied (key ${versionAfter}); web "${webRotation.slice(0, 50)}…", extension "${String(extRotation).slice(0, 50)}"`);

  assert.deepEqual(errors, []);
  log("all concurrent cross-client scenarios converged");
 } finally { await context.close(); }
})().catch(error => { console.error(`[${label}] FAILED`, error); process.exitCode = 1; });
