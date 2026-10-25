const { chromium } = require("playwright");
const fs = require("node:fs");
const path = require("node:path");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const root = path.resolve(__dirname, "../..");

(async () => {
  const worker = fs.readFileSync(path.join(root, "extension/service-worker.js"), "utf8");
  const ensure = worker.slice(worker.indexOf("async function ensureRecentGoogleSignIn("), worker.indexOf("async function authorize("));
  const calls = [];
  let recent = false;
  let cancelGoogle = true;
  const sandbox = { hasRecentGoogleSignIn: async () => recent, subject: async () => "owner",
    authorize: async (interactive, owner) => {
      calls.push({ interactive, owner });
      if (interactive && cancelGoogle) throw new Error("Google authentication cancelled");
      if (interactive) recent = true;
    },
    coded: (code, message) => Object.assign(new Error(message), { code }) };
  vm.createContext(sandbox);
  vm.runInContext(ensure, sandbox);
  await assert.rejects(sandbox.ensureRecentGoogleSignIn(), { code: "REAUTH_REQUIRED" });
  assert.equal(calls.some(call => call.interactive), false, "account chooser opened before confirmation");
  await assert.rejects(sandbox.ensureRecentGoogleSignIn({ confirmed: true }), (error) => error.code === "REAUTH_CANCELLED" && /cancelled\. Nothing was changed/.test(error.message));
  assert.equal(recent, false, "cancelling Google must not grant recent authentication");
  cancelGoogle = false;
  await sandbox.ensureRecentGoogleSignIn({ confirmed: true });
  assert.deepEqual(calls.at(-1), { interactive: true, owner: "owner" });
  calls.length = 0;
  await sandbox.ensureRecentGoogleSignIn();
  assert.equal(calls.length, 0, "fresh Google sign-in unexpectedly prompted again");
  // A silent Google renewal (prompt=none) is never used as proof that the user is present.
  recent = false; calls.length = 0;
  await assert.rejects(sandbox.ensureRecentGoogleSignIn(), { code: "REAUTH_REQUIRED" });
  assert.equal(calls.length, 0, "a silent Google sign-in was attempted for a protected action");

  // Rotation must fetch current lock metadata after authentication and before preparing new keys.
  const rotation = worker.slice(worker.indexOf("async function rotateEncryptionKey("), worker.indexOf("async function syncState("));
  const steps = [];
  let revision = 1, cancelRotationAuth = true, rejectPassphrase = false;
  const rotationContext = {
    activeAppSession: async () => {},
    ensureRecentGoogleSignIn: async () => { if (cancelRotationAuth) throw new Error("Google cancelled"); steps.push("auth"); },
    subject: async () => "owner",
    ensureServerFeatures: async () => {},
    api: async (url, options) => {
      if (url === "/api/v1/lock") { steps.push("lock"); return { wrappedKey: {}, vaultRevision: 7 }; }
      assert.equal(JSON.parse(options.body).expectedRevision, 7);
      steps.push("rotate"); return { entries: [], lock: { vaultRevision: 8 } };
    },
    LockstepVault: {
      refreshRotationKey: async (owner, key, current) => { revision = current; steps.push("adopt"); return true; },
      unlock: async () => { steps.push("unlock"); if (rejectPassphrase) throw new Error("Wrong passphrase"); },
      prepareMasterRotation: async () => { steps.push("prepare"); return { wrappedKey: {}, entries: [], previous: [], expectedRevision: revision }; },
      commitMasterRotation: async () => ({ version: 2, count: 0, recoveryKey: "test" })
    },
    chrome: { storage: { local: { set: async () => {}, get: async () => ({ cachedLockConfig: {} }) } } },
    rememberLockConfig: () => {},
    synchronize: async () => { steps.push("sync"); },
    clearUnlockedSession: async () => { steps.push("clear"); },
    persistUnlockedSession: async () => {}
  };
  vm.createContext(rotationContext); vm.runInContext(rotation, rotationContext);
  await assert.rejects(rotationContext.rotateEncryptionKey("test-passphrase"), /Google cancelled/);
  assert.equal(steps.length, 0, "cancelled authentication must not start rotation");
  cancelRotationAuth = false;
  await rotationContext.rotateEncryptionKey("test-passphrase");
  assert.deepEqual(steps, ["auth", "lock", "adopt", "unlock", "sync", "prepare", "rotate"]);
  steps.length = 0; rejectPassphrase = true;
  await assert.rejects(rotationContext.rotateEncryptionKey("old-passphrase"), /Wrong passphrase/);
  assert.deepEqual(steps, ["auth", "lock", "adopt", "unlock", "clear"]);

  const browser = await chromium.launch();
  try {
    const page = await browser.newPage({ viewport: { width: 380, height: 600 } });
    await page.route("http://localhost/**", route => {
      const name = new URL(route.request().url()).pathname.slice(1);
      if (name.endsWith(".js")) return route.fulfill({ contentType: "application/javascript", body: "" });
      const file = path.join(root, "extension", name);
      return route.fulfill({ contentType: name.endsWith(".css") ? "text/css" : name.endsWith(".svg") ? "image/svg+xml" : "text/html", body: fs.readFileSync(file) });
    });
    await page.goto("http://localhost/popup.html");
    const popup = fs.readFileSync(path.join(root, "extension/popup.js"), "utf8");
    const helper = popup.slice(popup.indexOf("async function confirmRecentGoogleSignIn("), popup.indexOf("async function send("));
    await page.addScriptTag({ content: 'const $=id=>document.getElementById(id);window.sent=[];window.chrome={runtime:{sendMessage:async message=>{sent.push(message);return {ok:true,data:"completed"}}}};' + helper });
    await page.evaluate(() => { window.pending = confirmRecentGoogleSignIn("ROTATE_ENCRYPTION_KEY", { passcode: "test-only" }); });
    await page.getByRole("dialog", { name: "Confirm it's you" }).waitFor();
    assert.match(await page.textContent("#reauth-message"), /rotate your recovery key/);
    assert.equal(await page.evaluate(() => sent.length), 0);
    await page.getByRole("button", { name: "Close", exact: true }).click();
    assert.equal((await page.evaluate(() => pending)).code, "REAUTH_CANCELLED");
    assert.equal(await page.evaluate(() => sent.length), 0);
    await page.evaluate(() => { window.pending = confirmRecentGoogleSignIn("ROTATE_ENCRYPTION_KEY", { passcode: "test-only" }); });
    await page.getByRole("button", { name: "Continue with Google" }).click();
    assert.equal((await page.evaluate(() => pending)).ok, true);
    assert.deepEqual(await page.evaluate(() => sent), [{ passcode: "test-only", type: "CONFIRM_RECENT_GOOGLE_SIGN_IN", action: "ROTATE_ENCRYPTION_KEY" }]);
    console.log("Extension security dialog: cancel, continue, recent-sign-in gate and account binding passed");
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
