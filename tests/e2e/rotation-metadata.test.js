// Exercise both real crypto modules without needing Chrome's extension launcher.
const { chromium } = require("playwright");
const assert = require("node:assert/strict");
const path = require("node:path");

(async () => {
  const browser = await chromium.launch();
  try {
    for (const client of ["webapp", "extension"]) {
      const context = await browser.newContext();
      try {
        const page = await context.newPage();
        await page.route("http://localhost/rotation-test", route => route.fulfill({ contentType: "text/html", body: "<!doctype html><title>Rotation test</title>" }));
        await page.goto("http://localhost/rotation-test");
        await page.addScriptTag({ path: path.resolve(__dirname, "../../", client, "vendor/argon2id.js") });
        await page.addScriptTag({ path: path.resolve(__dirname, "../../", client, "crypto-store.js") });
        for (const argon of [true, false]) {
          const result = await page.evaluate(async argon => {
            const vault = globalThis.LockstepVault;
            const subject = argon ? "argon-user" : "pbkdf2-user";
            const passphrase = "rotation-regression-passphrase";
            vault.setArgon2idWrapping(argon);
            await vault.configurePassphrase(subject, passphrase);
            await vault.markWrappedKeySynced(subject, 3, await vault.exportWrappedKey(subject));
            const remote = await vault.exportWrappedKey(subject);
            const recovery = await vault.exportRecoveryKey(subject);
            // Same master/version, independently re-wrapped locally: local revision 4, server revision 3.
            await vault.configurePassphrase(subject, passphrase);
            await vault.markWrappedKeySynced(subject, 4, await vault.exportWrappedKey(subject));
            const local = await vault.exportWrappedKey(subject);
            if (local.wrappedMasterKey === remote.wrappedMasterKey) throw new Error("fixture must contain different wrappers");
            const expectRefusal = async (key, password) => {
              try { await vault.refreshRotationKey(subject, key, 3, password); throw new Error("unsafe repair accepted"); }
              catch (error) { if (error.code !== "VAULT_STATE_MISMATCH") throw error; }
              if (await vault.expectedRevision(subject) !== 4 ||
                  (await vault.exportWrappedKey(subject)).wrappedMasterKey !== local.wrappedMasterKey) throw new Error("refused repair changed local state");
            };
            await expectRefusal(remote, "incorrect-passphrase");
            // An unrelated master encrypted under the same passphrase and subject must also be refused.
            const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
            const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
            const key = await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 600000 }, material,
              { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
            const cipher = await crypto.subtle.encrypt({ name: "AES-GCM", iv,
              additionalData: new TextEncoder().encode(`lockstep:master-key:${subject}`) }, key, crypto.getRandomValues(new Uint8Array(32)));
            const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
            const unrelated = { ...remote, wrapping: "PBKDF2-SHA256/AES-256-GCM", iterations: 600000,
              salt: b64(salt), iv: b64(iv), wrappedMasterKey: b64(cipher), memoryKiB: undefined, parallelism: undefined };
            await expectRefusal(unrelated, passphrase);
            await vault.refreshRotationKey(subject, remote, 3, passphrase);
            if (await vault.expectedRevision(subject) !== 3 || await vault.exportRecoveryKey(subject) !== recovery ||
                (await vault.exportWrappedKey(subject)).wrappedMasterKey !== remote.wrappedMasterKey) throw new Error("verified metadata repair failed");
            // An unsaved same-passphrase re-wrap must not strand a second client. Only accept it
            // after proving BOTH persisted wrappers decrypt to the exact same master.
            await vault.markWrappedKeySynced(subject, 4, await vault.exportWrappedKey(subject));
            await vault.configurePassphrase(subject, passphrase);
            if (!await vault.pendingWrappedKeyUpload(subject)) throw new Error("missing pending re-wrap fixture");
            await vault.refreshRotationKey(subject, remote, 3, passphrase);
            if (await vault.pendingWrappedKeyUpload(subject) || await vault.expectedRevision(subject) !== 3 ||
                await vault.exportRecoveryKey(subject) !== recovery) throw new Error("pending same-key repair failed");
            // Do not discard a real, unsaved passphrase change just to match an older server response.
            await vault.markWrappedKeySynced(subject, 4, await vault.exportWrappedKey(subject));
            await vault.configurePassphrase(subject, "different-new-passphrase");
            let refused = false;
            try { await vault.refreshRotationKey(subject, remote, 3, passphrase); }
            catch (error) { if (error.code !== "VAULT_STATE_MISMATCH") throw error; refused = true; }
            if (!refused || !await vault.pendingWrappedKeyUpload(subject) || await vault.expectedRevision(subject) !== 4)
              throw new Error("unsaved passphrase change was overwritten");
            await vault.configurePassphrase(subject, passphrase);
            await vault.refreshRotationKey(subject, remote, 3, passphrase);
            // Simulate another tab replacing the persisted wrapper while this context still holds
            // an unrelated, same-version session. Repair must use the passphrase-verified disk key.
            await vault.synchronizeWrappedKey(subject, unrelated, 4);
            await vault.unlock(subject, passphrase);
            await vault.addOtpUri(subject, "otpauth://totp/Pending:test?secret=JBSWY3DPEHPK3PXP&issuer=Pending");
            await new Promise((resolve, reject) => {
              const request = indexedDB.open("lockstep-vault");
              request.onerror = () => reject(request.error);
              request.onsuccess = () => {
                const database = request.result;
                const transaction = database.transaction("keys", "readwrite");
                transaction.objectStore("keys").put({ ...remote, id: subject + ":master", subject, serverRevision: 4 });
                transaction.oncomplete = () => { database.close(); resolve(); };
                transaction.onerror = () => { database.close(); reject(transaction.error); };
              };
            });
            refused = false;
            try { await vault.refreshRotationKey(subject, remote, 3, passphrase); }
            catch (error) { if (error.code !== "VAULT_STATE_MISMATCH") throw error; refused = true; }
            if (!refused || !await vault.pendingCount(subject) || await vault.exportRecoveryKey(subject) === recovery)
              throw new Error("repair discarded an old session's pending changes");
            // Acknowledge and remove this test-only draft, then exercise the no-pending repair.
            await vault.synchronize(subject, { put: async (id, entry) => ({ id, ...entry }), list: async () => [] });
            await vault.refreshRotationKey(subject, remote, 3, passphrase);
            if (await vault.exportRecoveryKey(subject) !== recovery) throw new Error("stale in-memory master survived verified repair");
            const prepared = await vault.prepareMasterRotation(subject, passphrase);
            try {
              if (prepared.expectedRevision !== 3) throw new Error("rotation still uses the stale local revision");
              return { key: prepared.wrappedKey,
                opens: await vault.passkeyOpensWrappedKey(subject, prepared.wrappedKey, passphrase) };
            } finally { vault.cancelMasterRotation(prepared); }
          }, argon);
          assert.equal(result.key.currentVersion, 2);
          assert.equal(result.opens, true, client + ": rotation key cannot be unwrapped from its wire metadata");
          if (argon) {
            assert.equal(result.key.wrapping, "ARGON2ID-V13/AES-256-GCM");
            assert.equal(result.key.iterations, 3);
            assert.equal(result.key.memoryKiB, 65536);
            assert.equal(result.key.parallelism, 1);
          } else {
            assert.equal(result.key.wrapping, "PBKDF2-SHA256/AES-256-GCM");
            assert.equal(result.key.iterations, 600000);
            assert.equal(result.key.memoryKiB, undefined);
            assert.equal(result.key.parallelism, undefined);
          }
          console.log(client + ": " + (argon ? "Argon2id" : "PBKDF2") + " rotation metadata and unwrap passed");
        }
      } finally { await context.close(); }
    }
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
