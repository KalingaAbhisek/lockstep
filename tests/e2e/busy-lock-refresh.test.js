const fs = require("node:fs"), path = require("node:path"), vm = require("node:vm"), assert = require("node:assert/strict");
function section(source, start, end) { return source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start))); }
(async () => {
 const web = fs.readFileSync(path.join(__dirname, "../../webapp/app.js"), "utf8");
 for (const changed of [false, true]) {
  let finish, requests = 0, applied = 0;
  const authentication = { subject: "A", generation: 1 };
  const box = { state: { vaultEpoch: 1 }, isVaultOperational: () => true,
   authenticationSnapshot: () => authentication, assertSyncCooldown() {},
   api: async (url, options) => { requests++; assert.equal(url, "/api/v1/lock"); assert.equal(options.expectedAuthentication, authentication); return new Promise(resolve => finish = resolve); },
   assertVaultOperation(epoch) { if (epoch !== box.state.vaultEpoch) throw new Error("View changed"); },
   applySynchronizedLock: async (owner, lock, snapshot) => { assert.equal(owner, "A"); assert.equal(snapshot, authentication); applied++; } };
  vm.createContext(box); vm.runInContext(section(web, "async function refreshLockWhileBusy(", "function isSecureGoogleOrigin("), box);
  const pending = box.refreshLockWhileBusy(); await box.refreshLockWhileBusy();
  assert.equal(requests, 1, "busy refreshes must coalesce");
  if (changed) box.state.vaultEpoch++;
  finish({ enabled: true }); await pending;
  assert.equal(applied, changed ? 0 : 1, "a stale response must not change a newer vault view");
  assert.equal(box.state.remoteLockChecking, false);
 }
 const popup = fs.readFileSync(path.join(__dirname, "../../extension/popup.js"), "utf8");
 let finish, requests = 0, hidden = true;
 const box = { lockConfig: { enabled: true }, $: () => ({ classList: { contains: () => hidden } }), send: () => { requests++; return new Promise(resolve => finish = resolve); } };
 vm.createContext(box); vm.runInContext(section(popup, "let remoteLockChecking =", "function refreshFromServer("), box);
 await box.refreshLockWhileBusy(); assert.equal(requests, 0, "setup and locked dialogs must not be interrupted by a remote lock check");
 hidden = false;
 const pending = box.refreshLockWhileBusy(); await box.refreshLockWhileBusy(); assert.equal(requests, 1);
 finish({ ok: true }); await pending;
 // While the passphrase is being created (no lock yet) there is nothing to check: asking would answer "locked"
 // and replace the setup screen with "unlock".
 box.lockConfig = { enabled: false }; await box.refreshLockWhileBusy(); assert.equal(requests, 1, "a remote lock check ran while the passphrase was being created");
 const worker = fs.readFileSync(path.join(__dirname, "../../extension/service-worker.js"), "utf8");
 const authentication = { owner: "A", generation: 1 }; let unlocked = true, reads = 0, applied = 0, keyState = "wrapped";
 const workerBox = { authenticationSnapshot: async () => authentication, LockstepVault: { isUnlocked: () => unlocked, keyState: async () => keyState },
  coded: (code, message) => Object.assign(new Error(message), { code }), assertSyncCooldown() {},
  api: async (url, options) => { assert.equal(url, "/api/v1/lock"); assert.equal(options.expectedAuthentication, authentication); reads++; return {}; },
  applySynchronizedLock: async (owner, lock, snapshot) => { assert.equal(owner, "A"); assert.equal(snapshot, authentication); applied++; } };
 vm.createContext(workerBox); vm.runInContext(section(worker, "async function checkRemoteLock(", "async function applySynchronizedLock("), workerBox);
 await workerBox.checkRemoteLock(); assert.equal(reads, 1); assert.equal(applied, 1);
 unlocked = false; await assert.rejects(workerBox.checkRemoteLock(), error => error.code === "VAULT_LOCKED"); assert.equal(reads, 1);
 keyState = "none"; assert.equal(await workerBox.checkRemoteLock(), false, "no vault key yet must not be reported as locked"); assert.equal(reads, 1);
 console.log("both clients: busy key checks coalesce, preserve locked/setup views and reject stale responses");
})().catch(error => { console.error(error); process.exitCode = 1; });
