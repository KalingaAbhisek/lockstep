// The extension (1) protects a new vault with Argon2id even right after its worker restarted, and (2) rotates
// the recovery key even when another device re-protected the key since (the server's revision moved on).
const API = `http://localhost:${process.env.API_PORT || 8080}`;
const { chromium } = require("playwright");
const path = require("path"), os = require("os"), fs = require("fs");
const [label, extDir] = [process.argv[2], process.argv[3]];
const control = (q) => fetch(`${API}/__control?${q}`).then(r => r.json());
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = () => { const iat = Math.floor(Date.now() / 1000); return `${b64({ alg: "RS256" })}.${b64({ sub: "user-1", name: "T", email: "t@example.com", iat, exp: iat + 3600 })}.sig`; };
const log = (...a) => console.log(`[${label}]`, ...a);
const failures = []; const check = (ok, message) => { if (!ok) failures.push(message); };

(async () => {
  await control("reset=1"); await fetch(`${API}/api/v1/session`, { method: "POST" });
  const context = await chromium.launchPersistentContext(fs.mkdtempSync(path.join(os.tmpdir(), `lockstep-profile-${label}-`)), { channel: "chromium", headless: true,
    ignoreDefaultArgs: ["--disable-extensions"], args: ["--headless=new", `--disable-extensions-except=${extDir}`, `--load-extension=${extDir}`] });
  let [worker] = context.serviceWorkers(); if (!worker) worker = await context.waitForEvent("serviceworker");
  for (let i = 0; i < 100; i++) { if (await worker.evaluate(() => Boolean(globalThis.chrome?.storage) && typeof setTimeout === "function").catch(() => false)) break; await new Promise(r => setTimeout(r, 100)); }
  // A freshly started worker that has not asked the server anything yet sets up the vault.
  const setup = await worker.evaluate(async (token) => {
    await chrome.storage.local.set({ vaultSubject: "user-1", vaultDisplayName: "T", appSessionId: "session-token", appSessionExpiry: Date.now() + 864e5 });
    await chrome.storage.session.set({ idToken: token, tokenExpiry: Date.now() + 3600e3, interactiveSignInAt: Date.now(), newAccountSetupAuthorized: true });
    await setLockConfig("first-passphrase-1", 300, false, true);
    await importEntries(["otpauth://totp/A:a@x.com?secret=JBSWY3DPEHPK3PXP&issuer=A"]);
    return { remembered: (await chrome.storage.local.get("serverFeatures")).serverFeatures };
  }, jwt());
  let st = await control("");
  log("new vault protected with:", st.wrapping, "| features remembered:", JSON.stringify(setup.remembered));
  check(st.wrapping === "ARGON2ID-V13/AES-256-GCM", `a new vault was protected with ${st.wrapping}`);
  check(Array.isArray(setup.remembered) && setup.remembered.includes("argon2idWrapping"), "the server's features were not remembered");
  // Another device re-protects the same key (same passphrase): the server's revision moves on while this
  // device still holds its older copy.
  const stale = await worker.evaluate(async () => {
    const owner = await subject();
    const db = await new Promise(r => { const q = indexedDB.open("lockstep-vault"); q.onsuccess = () => r(q.result); });
    const read = () => new Promise(r => { const q = db.transaction("keys").objectStore("keys").get(owner + ":master"); q.onsuccess = () => r(q.result); });
    const original = await read();
    await LockstepVault.configurePassphrase(owner, "first-passphrase-1");          // the other device's re-wrap
    const rewrapped = await LockstepVault.exportWrappedKey(owner);
    await api("/api/v1/lock", { method: "PUT", body: JSON.stringify({ timeoutSeconds: 300, lockOnScreenLock: false, wrappedKey: rewrapped, expectedRevision: original.serverRevision }) });
    await new Promise(r => { const tx = db.transaction("keys", "readwrite"); tx.objectStore("keys").put(original); tx.oncomplete = r; });  // this device: the older copy
    return { local: original.serverRevision };
  });
  st = await control("");
  log("this device expects revision", stale.local, "| server now:", st.revision);
  const rotation = await worker.evaluate(async () => {
    try { const r = await rotateEncryptionKey("first-passphrase-1"); return `rotated to version ${r.version}`; } catch (e) { return `${e.code}: ${e.message}`; }
  });
  st = await control("");
  log("rotation:", rotation, "| server key version:", st.keyVersion, "| wrapping:", st.wrapping);
  check(/rotated to version 2/.test(rotation) && st.keyVersion === 2, `the rotation failed: ${rotation}`);
  check(st.wrapping === "ARGON2ID-V13/AES-256-GCM", `the rotated key was protected with ${st.wrapping}`);
  const reopened = await worker.evaluate(async () => { await lockVault(); return (await verifyLock("first-passphrase-1")).unlocked; });
  check(reopened, "the rotated vault did not unlock");
  log("unlocks after the rotation:", reopened);
  await context.close();
  if (failures.length) { console.error(`[${label}] FAILED: ${failures.join("; ")}`); process.exit(1); }
  process.exit(0);
})().catch(e => { console.error(`[${label}] FAILED`, e.message); process.exit(1); });
