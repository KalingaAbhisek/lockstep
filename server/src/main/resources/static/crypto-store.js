/* Lockstep client vault: AES-GCM encryption, local TOTP generation, and offline outbox. */
(() => {
    const DB_NAME = "lockstep-vault";
    const DB_VERSION = 1;
    const WRAP_ITERATIONS = 600000;
    const unlockedMasters = new Map();
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    function requestResult(request) {
        return new Promise((resolve, reject) => {
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    function transactionDone(transaction) {
        return new Promise((resolve, reject) => {
            transaction.oncomplete = resolve;
            transaction.onerror = () => reject(transaction.error);
            transaction.onabort = () => reject(transaction.error || new Error("Local vault transaction was aborted"));
        });
    }

    function openDatabase() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(DB_NAME, DB_VERSION);
            request.onupgradeneeded = () => {
                const database = request.result;
                if (!database.objectStoreNames.contains("keys")) database.createObjectStore("keys", { keyPath: "id" });
                if (!database.objectStoreNames.contains("entries")) database.createObjectStore("entries", { keyPath: "storageId" });
                if (!database.objectStoreNames.contains("outbox")) database.createObjectStore("outbox", { keyPath: "mutationId" });
            };
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
    }

    async function all(storeName) {
        const database = await openDatabase();
        const transaction = database.transaction(storeName, "readonly");
        const result = await requestResult(transaction.objectStore(storeName).getAll());
        await transactionDone(transaction);
        database.close();
        return result;
    }

    async function get(storeName, key) {
        const database = await openDatabase();
        const transaction = database.transaction(storeName, "readonly");
        const result = await requestResult(transaction.objectStore(storeName).get(key));
        await transactionDone(transaction);
        database.close();
        return result;
    }

    async function put(storeName, value) {
        const database = await openDatabase();
        const transaction = database.transaction(storeName, "readwrite");
        transaction.objectStore(storeName).put(value);
        await transactionDone(transaction);
        database.close();
    }

    function storageId(subject, id) { return subject + ":" + id; }
    function keyId(subject, version) { return subject + ":" + version; }
    function bytesToBase64(bytes) {
        let binary = "";
        for (let offset = 0; offset < bytes.length; offset += 8192) {
            binary += String.fromCharCode(...bytes.subarray(offset, offset + 8192));
        }
        return btoa(binary);
    }
    function base64ToBytes(value) {
        const binary = atob(value);
        return Uint8Array.from(binary, character => character.charCodeAt(0));
    }
    function base64Url(bytes) {
        return bytesToBase64(bytes).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
    }
    function fromBase64Url(value) {
        const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
        return base64ToBytes(normalized + "=".repeat((4 - normalized.length % 4) % 4));
    }
    function associatedData(subject, id, version) {
        return encoder.encode(`lockstep:v2:${subject}:${id}:${version}`);
    }

    function masterKeyId(subject) { return subject + ":master"; }

    function requirePassphrase(passphrase) {
        if (typeof passphrase !== "string" || passphrase.length < 4 || passphrase.length > 128) {
            throw new Error("Passkey must contain 4 to 128 characters.");
        }
    }

    async function wrappingKey(passphrase, salt, iterations, usage) {
        const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", hash: "SHA-256", salt, iterations }, material,
            { name: "AES-GCM", length: 256 }, false, usage
        );
    }

    async function wrappedMasterRecord(subject, raw, currentVersion, passphrase, createdAt = Date.now()) {
        requirePassphrase(passphrase);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await wrappingKey(passphrase, salt, WRAP_ITERATIONS, ["encrypt"]);
        const wrapped = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: encoder.encode(`lockstep:master-key:${subject}`), tagLength: 128 },
            key, raw
        );
        return {
            id: masterKeyId(subject), subject, currentVersion, createdAt, wrappedAt: Date.now(),
            wrapping: "PBKDF2-SHA256/AES-256-GCM", iterations: WRAP_ITERATIONS,
            salt: bytesToBase64(salt), iv: bytesToBase64(iv), wrappedMasterKey: bytesToBase64(new Uint8Array(wrapped))
        };
    }

    async function importMaster(raw) {
        return crypto.subtle.importKey("raw", raw, "HKDF", false, ["deriveKey"]);
    }

    async function deriveVersionKey(master, subject, version) {
        if (version === 1) {
            return crypto.subtle.importKey("raw", base64ToBytes(master.raw), { name: "AES-GCM" }, false, ["encrypt", "decrypt"]);
        }
        return crypto.subtle.deriveKey(
            { name: "HKDF", hash: "SHA-256", salt: encoder.encode(subject), info: encoder.encode(`lockstep:entry-key:${version}`) },
            master.key, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
        );
    }

    async function masterKey(subject, create = false) {
        const memory = unlockedMasters.get(subject);
        if (memory) return memory;
        const existing = await get("keys", masterKeyId(subject));
        if (existing) throw new Error("Vault is locked. Enter your passkey to continue.");
        const legacy = await get("keys", keyId(subject, 1));
        if (legacy || create) throw new Error("Protect this vault with an App Lock passkey before using it.");
        return null;
    }

    async function currentKey(subject, create = false) {
        const master = await masterKey(subject, create);
        if (!master) return null;
        return keyFor(subject, master.currentVersion);
    }

    async function keyFor(subject, version) {
        const master = await masterKey(subject, false);
        if (!master) return null;
        const record = { id: keyId(subject, version), subject, version, key: await deriveVersionKey(master, subject, version), createdAt: Date.now() };
        if (version > master.currentVersion) {
            master.currentVersion = version;
            const persisted = await get("keys", masterKeyId(subject));
            if (persisted) { persisted.currentVersion = version; await put("keys", persisted); }
        }
        return record;
    }

    async function configurePassphrase(subject, passphrase) {
        requirePassphrase(passphrase);
        const persisted = await get("keys", masterKeyId(subject));
        let master = unlockedMasters.get(subject);
        if (!master && persisted?.wrappedMasterKey) {
            // A previous setup attempt may have wrapped the local master key before
            // the server-side lock configuration was saved. Treat the same passkey
            // as an idempotent setup retry instead of permanently stranding the vault.
            try {
                await unlock(subject, passphrase);
                master = unlockedMasters.get(subject);
            } catch {
                throw new Error("This browser already has a protected vault. Enter its existing passkey to continue setup.");
            }
        }
        if (!master) {
            const legacy = persisted?.raw ? persisted : await get("keys", keyId(subject, 1));
            const raw = legacy?.raw ? base64ToBytes(legacy.raw)
                : legacy?.key ? new Uint8Array(await crypto.subtle.exportKey("raw", legacy.key))
                : crypto.getRandomValues(new Uint8Array(32));
            master = { raw: bytesToBase64(raw), key: await importMaster(raw), currentVersion: persisted?.currentVersion || 1, createdAt: persisted?.createdAt || Date.now() };
        }
        const raw = base64ToBytes(master.raw);
        await put("keys", await wrappedMasterRecord(subject, raw, master.currentVersion, passphrase, master.createdAt));
        const database = await openDatabase();
        const transaction = database.transaction("keys", "readwrite");
        const store = transaction.objectStore("keys");
        for (const record of await requestResult(store.getAll())) {
            if (record.subject === subject && record.id !== masterKeyId(subject)) store.delete(record.id);
        }
        await transactionDone(transaction); database.close();
        unlockedMasters.set(subject, master);
        return true;
    }

    async function unlock(subject, passphrase) {
        requirePassphrase(passphrase);
        const record = await get("keys", masterKeyId(subject));
        if (!record?.wrappedMasterKey) {
            if (await keyState(subject) === "legacy") {
                await configurePassphrase(subject, passphrase);
                return true;
            }
            throw coded("KEY_MISSING", "This device does not have your vault key. Restore it with your recovery key.");
        }
        try {
            const key = await wrappingKey(passphrase, base64ToBytes(record.salt), record.iterations, ["decrypt"]);
            const raw = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: base64ToBytes(record.iv), additionalData: encoder.encode(`lockstep:master-key:${subject}`), tagLength: 128 },
                key, base64ToBytes(record.wrappedMasterKey)
            ));
            unlockedMasters.set(subject, { raw: bytesToBase64(raw), key: await importMaster(raw), currentVersion: record.currentVersion, createdAt: record.createdAt });
            return true;
        } catch { throw coded("WRONG_PASSKEY", "Incorrect passkey."); }
    }

    function coded(code, message) { const error = new Error(message); error.code = code; return error; }

    async function keyState(subject) {
        const record = await get("keys", masterKeyId(subject));
        if (record?.wrappedMasterKey) return "wrapped";
        if (record?.raw || await get("keys", keyId(subject, 1))) return "legacy";
        return "none";
    }

    async function exportWrappedKey(subject) {
        const record = await get("keys", masterKeyId(subject));
        if (!record?.wrappedMasterKey) return null;
        return { currentVersion: record.currentVersion, createdAt: record.createdAt, wrappedAt: record.wrappedAt || record.createdAt,
            wrapping: record.wrapping, iterations: record.iterations, salt: record.salt, iv: record.iv, wrappedMasterKey: record.wrappedMasterKey };
    }

    async function synchronizeWrappedKey(subject, remote) {
        if (!remote?.wrappedMasterKey) return false;
        const local = await get("keys", masterKeyId(subject));
        const remoteWrappedAt = Number(remote.wrappedAt || remote.createdAt || 0);
        const localWrappedAt = Number(local?.wrappedAt || local?.createdAt || 0);
        if (local?.wrappedMasterKey && remoteWrappedAt <= localWrappedAt) return false;
        await put("keys", { id: masterKeyId(subject), subject, currentVersion: remote.currentVersion, createdAt: remote.createdAt,
            wrappedAt: remoteWrappedAt, wrapping: remote.wrapping, iterations: remote.iterations,
            salt: remote.salt, iv: remote.iv, wrappedMasterKey: remote.wrappedMasterKey });
        unlockedMasters.delete(subject);
        return true;
    }

    function lock(subject) { unlockedMasters.delete(subject); }
    function isUnlocked(subject) { return unlockedMasters.has(subject); }

    function validateUuidV4(value, field = "ID") {
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
            throw new Error(field + " must be a UUIDv4.");
        }
    }

    function parseOtpAuthUri(uri) {
        let parsed;
        try { parsed = new URL(uri); } catch { throw new Error("Invalid authenticator URI."); }
        if (parsed.protocol !== "otpauth:" || parsed.hostname.toLowerCase() !== "totp") {
            throw new Error("Only otpauth://totp entries are supported.");
        }
        const secret = (parsed.searchParams.get("secret") || "").toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
        if (!/^[A-Z2-7]+$/.test(secret)) throw new Error("TOTP secret must use valid Base32 characters.");
        let label;
        try { label = decodeURIComponent(parsed.pathname.replace(/^\//, "")); } catch { throw new Error("Invalid authenticator label."); }
        const separator = label.indexOf(":");
        const labelIssuer = separator >= 0 ? label.slice(0, separator).trim() : "";
        const accountName = (separator >= 0 ? label.slice(separator + 1) : label).trim();
        const issuer = (parsed.searchParams.get("issuer") || labelIssuer).trim();
        const algorithm = (parsed.searchParams.get("algorithm") || "SHA1").toUpperCase().replace("-", "");
        const digits = Number(parsed.searchParams.get("digits") || 6);
        const periodSeconds = Number(parsed.searchParams.get("period") || 30);
        if (!issuer || issuer.length > 128) throw new Error("Issuer is required and must be at most 128 characters.");
        if (!accountName || accountName.length > 256) throw new Error("Account name is required and must be at most 256 characters.");
        if (!["SHA1", "SHA256", "SHA512"].includes(algorithm)) throw new Error("Unsupported TOTP algorithm.");
        if (![6, 7, 8].includes(digits)) throw new Error("TOTP digits must be between 6 and 8.");
        if (!Number.isInteger(periodSeconds) || periodSeconds < 15 || periodSeconds > 120) throw new Error("TOTP period must be between 15 and 120 seconds.");
        return { issuer, accountName, secret, algorithm, digits, periodSeconds };
    }

    async function encryptSecret(subject, id, plaintext, keyRecord) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: associatedData(subject, id, keyRecord.version), tagLength: 128 },
            keyRecord.key,
            encoder.encode(plaintext)
        );
        return { encryptedSecret: bytesToBase64(new Uint8Array(ciphertext)), secretIv: bytesToBase64(iv), keyVersion: keyRecord.version };
    }

    async function decryptSecret(subject, entry) {
        const keyRecord = await keyFor(subject, entry.keyVersion);
        if (!keyRecord) throw new Error(`Recovery key required for encryption key version ${entry.keyVersion}.`);
        try {
            const plaintext = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: base64ToBytes(entry.secretIv), additionalData: associatedData(subject, entry.id, entry.keyVersion), tagLength: 128 },
                keyRecord.key,
                base64ToBytes(entry.encryptedSecret)
            );
            return decoder.decode(plaintext);
        } catch {
            throw new Error("This device cannot decrypt the authenticator vault. Import the correct recovery key.");
        }
    }

    function base32Bytes(value) {
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let bits = "", output = [];
        for (const character of value.replace(/=+$/, "").toUpperCase()) {
            const index = alphabet.indexOf(character);
            if (index < 0) throw new Error("Invalid Base32 secret.");
            bits += index.toString(2).padStart(5, "0");
        }
        for (let offset = 0; offset + 8 <= bits.length; offset += 8) output.push(parseInt(bits.slice(offset, offset + 8), 2));
        return new Uint8Array(output);
    }

    async function totp(secret, algorithm, digits, periodSeconds, now = Date.now()) {
        const counter = Math.floor(now / 1000 / periodSeconds);
        const message = new ArrayBuffer(8);
        const view = new DataView(message);
        view.setUint32(0, Math.floor(counter / 0x100000000));
        view.setUint32(4, counter >>> 0);
        const key = await crypto.subtle.importKey("raw", base32Bytes(secret), { name: "HMAC", hash: algorithm.replace("SHA", "SHA-") }, false, ["sign"]);
        const digest = new Uint8Array(await crypto.subtle.sign("HMAC", key, message));
        const offset = digest[digest.length - 1] & 0x0f;
        const binary = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
        const code = String(binary % (10 ** digits)).padStart(digits, "0");
        const validUntilEpochMillis = (counter + 1) * periodSeconds * 1000;
        return { code, validUntilEpochMillis, secondsRemaining: Math.ceil((validUntilEpochMillis - now) / 1000) };
    }

    async function localEncryptedEntries(subject) {
        return (await all("entries")).filter(entry => entry.subject === subject).sort((a, b) => a.createdAtEpochMillis - b.createdAtEpochMillis);
    }

    function wireEntry(entry) {
        const { storageId: ignoredStorageId, subject: ignoredSubject, ...wire } = entry;
        return wire;
    }

    async function publicEntry(subject, entry, now = Date.now()) {
        const secret = await decryptSecret(subject, entry);
        const generated = await totp(secret, entry.algorithm, entry.digits, entry.periodSeconds, now);
        return { ...wireEntry(entry), ...generated, period: entry.periodSeconds, serverEpochMillis: now, validForMillis: generated.validUntilEpochMillis - now };
    }

    async function listEntries(subject) {
        const now = Date.now();
        const result = [];
        for (const entry of await localEncryptedEntries(subject)) result.push(await publicEntry(subject, entry, now));
        return result;
    }

    async function writeEntryAndOutbox(subject, entry, operation = "PUT") {
        const database = await openDatabase();
        const transaction = database.transaction(["entries", "outbox"], "readwrite");
        const stored = { ...entry, subject, storageId: storageId(subject, entry.id) };
        if (operation === "PUT") transaction.objectStore("entries").put(stored);
        else transaction.objectStore("entries").delete(stored.storageId);
        transaction.objectStore("outbox").put({
            mutationId: entry.mutationId || crypto.randomUUID(), subject, entryId: entry.id,
            operation, payload: operation === "PUT" ? wireEntry(stored) : null, createdAt: Date.now(), attempts: 0
        });
        await transactionDone(transaction);
        database.close();
        return stored;
    }

    async function addOtpUri(subject, uri) {
        const parsed = parseOtpAuthUri(uri);
        const id = crypto.randomUUID();
        const mutationId = crypto.randomUUID();
        const keyRecord = await currentKey(subject, true);
        const encrypted = await encryptSecret(subject, id, parsed.secret, keyRecord);
        const entry = {
            id, issuer: parsed.issuer, accountName: parsed.accountName, ...encrypted,
            algorithm: parsed.algorithm, digits: parsed.digits, periodSeconds: parsed.periodSeconds,
            createdAtEpochMillis: Date.now(), updatedAtEpochMillis: Date.now(), mutationId
        };
        await writeEntryAndOutbox(subject, entry);
        return publicEntry(subject, { ...entry, subject, storageId: storageId(subject, id) });
    }

    async function updateEntry(subject, id, issuer, accountName) {
        validateUuidV4(id, "Entry ID");
        const entry = await get("entries", storageId(subject, id));
        if (!entry) throw new Error("Authenticator entry was not found.");
        const mutationId = crypto.randomUUID();
        const updated = { ...entry, issuer: issuer.trim(), accountName: accountName.trim(), mutationId, updatedAtEpochMillis: Date.now() };
        await writeEntryAndOutbox(subject, updated);
        return publicEntry(subject, updated);
    }

    async function deleteEntry(subject, id) {
        validateUuidV4(id, "Entry ID");
        await writeEntryAndOutbox(subject, { id, mutationId: crypto.randomUUID() }, "DELETE");
    }

    async function replaceFromServer(subject, remoteEntries) {
        const pending = (await all("outbox")).filter(item => item.subject === subject);
        const pendingIds = new Set(pending.map(item => item.entryId));
        const database = await openDatabase();
        const transaction = database.transaction("entries", "readwrite");
        const store = transaction.objectStore("entries");
        const existing = (await requestResult(store.getAll())).filter(entry => entry.subject === subject);
        const remoteIds = new Set(remoteEntries.map(entry => entry.id));
        for (const entry of existing) {
            if (!remoteIds.has(entry.id) && !pendingIds.has(entry.id)) store.delete(entry.storageId);
        }
        for (const entry of remoteEntries) {
            validateUuidV4(entry.id, "Server entry ID");
            if (!pendingIds.has(entry.id)) store.put({ ...entry, subject, storageId: storageId(subject, entry.id) });
        }
        await transactionDone(transaction);
        database.close();
    }

    async function removeOutbox(mutationId) {
        const database = await openDatabase();
        const transaction = database.transaction("outbox", "readwrite");
        transaction.objectStore("outbox").delete(mutationId);
        await transactionDone(transaction);
        database.close();
    }

    async function synchronize(subject, transport) {
        const queue = (await all("outbox")).filter(item => item.subject === subject).sort((a, b) => a.createdAt - b.createdAt);
        let synced = 0;
        for (const item of queue) {
            if (item.operation === "PUT") await transport.put(item.entryId, item.payload);
            else await transport.delete(item.entryId, item.mutationId);
            await removeOutbox(item.mutationId);
            synced++;
        }
        const remote = await transport.list();
        await replaceFromServer(subject, remote);
        return { synced, pending: (await all("outbox")).filter(item => item.subject === subject).length };
    }

    async function pendingCount(subject) {
        return (await all("outbox")).filter(item => item.subject === subject).length;
    }

    async function otpAuthUri(subject, id) {
        const entry = await get("entries", storageId(subject, id));
        if (!entry) throw new Error("Authenticator entry was not found.");
        const secret = await decryptSecret(subject, entry);
        const label = encodeURIComponent(entry.issuer + ":" + entry.accountName);
        const parameters = new URLSearchParams({
            secret, issuer: entry.issuer, algorithm: entry.algorithm, digits: String(entry.digits), period: String(entry.periodSeconds)
        });
        return `otpauth://totp/${label}?${parameters}`;
    }

    async function exportText(subject) {
        const uris = [];
        for (const entry of await localEncryptedEntries(subject)) uris.push(await otpAuthUri(subject, entry.id));
        return "# Lockstep TOTP backup\n# Keep this file private. Each URI contains an authenticator secret.\n" + uris.join("\n") + (uris.length ? "\n" : "");
    }

    async function exportRecoveryKey(subject) {
        const master = await masterKey(subject, false);
        if (!master) throw new Error("This vault does not have a local encryption key yet.");
        const raw = base64ToBytes(master.raw);
        return `LS2-M-${base64Url(raw)}`;
    }

    async function importRecoveryKey(subject, recoveryKey, passphrase) {
        requirePassphrase(passphrase);
        const match = /^LS2-M-([A-Za-z0-9_-]{43})$/.exec(recoveryKey.trim());
        if (!match) throw new Error("Invalid Lockstep recovery key.");
        const raw = fromBase64Url(match[1]);
        if (raw.length !== 32) throw new Error("Recovery key must contain 256 bits.");
        const candidateEntries = await localEncryptedEntries(subject);
        if (candidateEntries.length === 0) {
            throw new Error("No encrypted accounts are available to verify this recovery key. Reset the vault to start again.");
        }
        const currentVersion = Math.max(1, ...candidateEntries.map(entry => entry.keyVersion));
        const candidateMaster = { raw: bytesToBase64(raw), key: await importMaster(raw) };
        const candidate = candidateEntries.find(entry => entry.keyVersion === currentVersion);
        try {
            const key = await deriveVersionKey(candidateMaster, subject, candidate.keyVersion);
            await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: base64ToBytes(candidate.secretIv), additionalData: associatedData(subject, candidate.id, candidate.keyVersion), tagLength: 128 },
                key, base64ToBytes(candidate.encryptedSecret)
            );
        } catch { throw new Error("This recovery key does not match the encrypted vault."); }
        const record = await wrappedMasterRecord(subject, raw, currentVersion, passphrase);
        await put("keys", record);
        unlockedMasters.set(subject, { ...candidateMaster, currentVersion, createdAt: record.createdAt });
        return currentVersion;
    }

    async function rotateKey(subject) {
        const entries = await localEncryptedEntries(subject);
        const plaintext = [];
        for (const entry of entries) plaintext.push([entry, await decryptSecret(subject, entry)]);
        const master = await masterKey(subject, true);
        const version = master.currentVersion + 1;
        master.currentVersion = version;
        const persisted = await get("keys", masterKeyId(subject));
        if (!persisted?.wrappedMasterKey) throw new Error("Vault wrapping metadata is missing.");
        persisted.currentVersion = version;
        await put("keys", persisted);
        const keyRecord = await keyFor(subject, version);
        for (const [entry, secret] of plaintext) {
            const encrypted = await encryptSecret(subject, entry.id, secret, keyRecord);
            const updated = { ...entry, ...encrypted, mutationId: crypto.randomUUID(), updatedAtEpochMillis: Date.now() };
            await writeEntryAndOutbox(subject, updated);
        }
        return { version, count: entries.length, recoveryKey: await exportRecoveryKey(subject) };
    }

    // True key rotation: brand-new 256-bit master key, every account re-encrypted under it, new passkey wrap.
    // The new wrapped key, re-encrypted entries and their outbox mutations are committed in ONE IndexedDB
    // transaction, so a failure can never leave entries encrypted under a key that was not saved.
    async function rotateMasterKey(subject, passphrase) {
        requirePassphrase(passphrase);
        await unlock(subject, passphrase); // proves the passkey and loads the current master
        const entries = await localEncryptedEntries(subject);
        const plaintext = [];
        for (const entry of entries) plaintext.push([entry, await decryptSecret(subject, entry)]);
        const previous = unlockedMasters.get(subject);
        const version = previous.currentVersion + 1;
        const raw = crypto.getRandomValues(new Uint8Array(32));
        const createdAt = Date.now();
        const master = { raw: bytesToBase64(raw), key: await importMaster(raw), currentVersion: version, createdAt };
        const keyRecord = { id: keyId(subject, version), subject, version, key: await deriveVersionKey(master, subject, version), createdAt };
        const wrapped = await wrappedMasterRecord(subject, raw, version, passphrase, createdAt);
        const updated = [];
        for (const [entry, secret] of plaintext) {
            const encrypted = await encryptSecret(subject, entry.id, secret, keyRecord);
            updated.push({ ...entry, ...encrypted, mutationId: crypto.randomUUID(), updatedAtEpochMillis: Date.now() });
        }
        const database = await openDatabase();
        const transaction = database.transaction(["keys", "entries", "outbox"], "readwrite");
        transaction.objectStore("keys").put(wrapped);
        for (const entry of updated) {
            transaction.objectStore("entries").put(entry);
            transaction.objectStore("outbox").put({
                mutationId: entry.mutationId, subject, entryId: entry.id, operation: "PUT",
                payload: wireEntry(entry), createdAt: Date.now(), attempts: 0
            });
        }
        await transactionDone(transaction);
        database.close();
        unlockedMasters.set(subject, master);
        return { version, count: updated.length, recoveryKey: `LS2-M-${base64Url(raw)}`, wrappedKey: await exportWrappedKey(subject) };
    }

    async function clearSubject(subject) {
        const database = await openDatabase();
        const transaction = database.transaction(["keys", "entries", "outbox"], "readwrite");
        for (const storeName of ["keys", "entries", "outbox"]) {
            const store = transaction.objectStore(storeName);
            for (const record of await requestResult(store.getAll())) {
                if (record.subject !== subject) continue;
                const key = storeName === "keys" ? record.id : storeName === "entries" ? record.storageId : record.mutationId;
                store.delete(key);
            }
        }
        await transactionDone(transaction);
        database.close();
        unlockedMasters.delete(subject);
    }

    globalThis.LockstepVault = {
        addOtpUri, clearSubject, configurePassphrase, deleteEntry, exportRecoveryKey, exportText, exportWrappedKey, importRecoveryKey, isUnlocked, keyState, listEntries, lock,
        localEncryptedEntries, otpAuthUri, parseOtpAuthUri, pendingCount, rotateKey, rotateMasterKey, synchronize, synchronizeWrappedKey, unlock, updateEntry
    };
})();

