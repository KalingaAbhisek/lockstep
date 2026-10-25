const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const path = require("node:path");

(async () => {
  const browser = await chromium.launch();
  try {
    for (const creator of ["webapp", "extension"]) {
      const contexts = [];
      const clients = {};
      try {
        for (const client of ["webapp", "extension"]) {
          const context = await browser.newContext(); contexts.push(context);
          const page = await context.newPage(); clients[client] = page;
          await page.route("http://localhost/vault-test", r => r.fulfill({ contentType: "text/html", body: "<!doctype html><title>Vault test</title>" }));
          await page.goto("http://localhost/vault-test");
          await page.addScriptTag({ path: path.resolve(__dirname, "../../", client, "vendor/argon2id.js") });
          await page.addScriptTag({ path: path.resolve(__dirname, "../../", client, "crypto-store.js") });
          await page.evaluate(() => {
            globalThis.owner = "shared-owner";
            globalThis.password = "shared-vault-passphrase";
            LockstepVault.setArgon2idWrapping(true);
          });
        }
        const other = creator === "webapp" ? "extension" : "webapp";
        let server = await clients[creator].evaluate(async () => {
          await LockstepVault.configurePassphrase(owner, password);
          await LockstepVault.markWrappedKeySynced(owner, 1, await LockstepVault.exportWrappedKey(owner));
          await LockstepVault.addOtpUri(owner, "otpauth://totp/Test:shared?secret=JBSWY3DPEHPK3PXP&issuer=Test");
          const entries = await LockstepVault.localEncryptedEntries(owner);
          await LockstepVault.synchronize(owner, { put: async (id, entry) => ({ id, ...entry }), list: async () => entries });
          return { key: await LockstepVault.exportWrappedKey(owner), entries, revision: 1 };
        });
        for (const client of [other, creator]) {
          server = await clients[client].evaluate(async server => {
            await LockstepVault.synchronizeWrappedKey(owner, server.key, server.revision);
            await LockstepVault.unlock(owner, password);
            await LockstepVault.synchronize(owner, { put: async (id, entry) => ({ id, ...entry }), list: async () => server.entries });
            const before = await LockstepVault.exportText(owner);
            await LockstepVault.refreshRotationKey(owner, server.key, server.revision, password);
            const prepared = await LockstepVault.prepareMasterRotation(owner, password);
            if (prepared.expectedRevision !== server.revision) throw new Error("stale rotation revision");
            await LockstepVault.commitMasterRotation(prepared, prepared.entries, server.revision + 1);
            if (await LockstepVault.exportText(owner) !== before) throw new Error("rotation changed account secrets");
            return { key: prepared.wrappedKey, entries: prepared.entries, revision: server.revision + 1 };
          }, server);
        }
        // The other client must adopt the latest rotation and still decrypt the accounts.
        const text = await clients[other].evaluate(async server => {
          await LockstepVault.synchronizeWrappedKey(owner, server.key, server.revision);
          await LockstepVault.unlock(owner, password);
          await LockstepVault.synchronize(owner, { put: async (id, entry) => ({ id, ...entry }), list: async () => server.entries });
          return LockstepVault.exportText(owner);
        }, server);
        assert.match(text, /JBSWY3DPEHPK3PXP/);
        assert.equal(server.key.currentVersion, 3);
        console.log(`${creator} creation: ${other} rotation, reverse rotation and shared-secret preservation passed`);
        for (const client of ["webapp", "extension"]) {
          const result = await clients[client].evaluate(async () => {
            const tab = "session-regression";
            const oldSnapshot = await LockstepVault.exportSessionKey(owner, tab);
            await LockstepVault.configurePassphrase(owner, password);
            const currentSnapshot = await LockstepVault.exportSessionKey(owner, tab);
            LockstepVault.lock(owner);
            const acceptedStale = await LockstepVault.restoreSessionKey(owner, oldSnapshot, tab);
            LockstepVault.lock(owner);
            const acceptedCurrent = await LockstepVault.restoreSessionKey(owner, currentSnapshot, tab);
            LockstepVault.lock(owner);
            delete currentSnapshot.wrappedMasterKey;
            const acceptedLegacy = await LockstepVault.restoreSessionKey(owner, currentSnapshot, tab);
            await LockstepVault.unlock(owner, password);
            return { acceptedStale, acceptedCurrent, acceptedLegacy };
          });
          assert.deepEqual(result, { acceptedStale: false, acceptedCurrent: true, acceptedLegacy: false });
          console.log(`${client}: stale and unbound sessions rejected; current session restored`);
        }
      } finally { for (const context of contexts) await context.close(); }
    }
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
