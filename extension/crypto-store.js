/* Lockstep client vault: AES-GCM encryption, local TOTP generation, and offline outbox. */
(() => {
    const DB_NAME = "lockstep-vault";
    const DB_VERSION = 3;
    const WRAP_ITERATIONS = 600000;
    const FLUSH_BATCH_SIZE = 25;
    const syncGenerations = new Map();
    const unlockedMasters = new Map();
    const lockGenerations = new Map();
    const activeWriteTransactions = new Map();
    const outboxFlushes = new Map();
    const syncRuns = new Map();
    const sessionExportRuns = new Map();
    // Latest vault revision seen from the server per account (the server counts wrapped-key changes).
    const knownRevisions = new Map();
    // Accounts whose recovery key is being rotated: local changes and syncs wait until it finishes.
    const rotatingSubjects = new Map();
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();

    function vaultWrite(subject, action, wait = false) {
        if (!navigator?.locks?.request) return action();
        return navigator.locks.request(`lockstep-vault-rotation:${subject}`, { mode: "shared", ...(!wait ? { ifAvailable: true } : {}) }, lock => {
            if (!lock) throw coded("ROTATION_IN_PROGRESS", "The vault is changing in another tab. Try again in a moment.");
            return navigator.locks.request(`lockstep-vault-write:${subject}`, action);
        });
    }
    async function holdRotationWrite(subject) {
        if (!navigator?.locks?.request) return () => {};
        return new Promise((resolve, reject) => {
            navigator.locks.request(`lockstep-vault-rotation:${subject}`, { ifAvailable: true }, async lock => {
                if (!lock) { reject(coded("ROTATION_IN_PROGRESS", "The vault is changing in another tab. Try again in a moment.")); return; }
                await new Promise(release => resolve(release));
            }).catch(reject);
        });
    }
    function localStateId(subject) { return `${subject}:local-state`; }
    async function localGeneration(subject) { return (await get("keys", localStateId(subject)))?.generation || 0; }
    // Read the key identity and erasure fence from one IndexedDB snapshot.
    async function masterState(subject) {
        const database=await openDatabase(),transaction=database.transaction("keys","readonly");
        const done=transactionDone(transaction),store=transaction.objectStore("keys");
        const [record,state]=await Promise.all([requestResult(store.get(masterKeyId(subject))),requestResult(store.get(localStateId(subject))),done]);
        return {record,erasureGeneration:state?.erasureGeneration || 0};
    }
    async function assertMasterState(subject,expected,ticket) {
        const current=await masterState(subject);
        assertOperationTicket(subject,ticket,false);
        if(current.erasureGeneration!==expected.erasureGeneration || !current.record?.wrappedMasterKey ||
            current.record.wrappedMasterKey!==expected.record?.wrappedMasterKey || current.record.currentVersion!==expected.record?.currentVersion) {
            lock(subject);throw coded("VAULT_LOCKED","This vault was removed or changed while unlocking. Sign in again.");
        }
    }
    async function advanceLocalState(transaction, subject, queued = false) {
        const store = transaction.objectStore("keys");
        const previous = await requestResult(store.get(localStateId(subject)));
        const state = { id: localStateId(subject), subject, localState: true,
            generation: (previous?.generation || 0) + 1, erasureGeneration:previous?.erasureGeneration || 0, sequence: (previous?.sequence || 0) + (queued ? 1 : 0) };
        store.put(state);
        return state.sequence;
    }

    function lockGeneration(subject) { return lockGenerations.get(subject) || 0; }
    function operationTicket(subject, requireUnlocked = true) {
        if(requireUnlocked&&!unlockedMasters.has(subject))throw coded("VAULT_LOCKED","Vault locked. Unlock it to continue.");
        return lockGeneration(subject);
    }
    function assertOperationTicket(subject, ticket, requireUnlocked = true) {
        if(lockGeneration(subject)!==ticket||requireUnlocked&&!unlockedMasters.has(subject))throw coded("VAULT_LOCKED","Vault locked. Unlock it to continue.");
    }
    function assertNotRotating(subject) {
        if(rotatingSubjects.has(subject))throw coded("ROTATION_IN_PROGRESS","The recovery key is being rotated. Try again in a moment.");
    }
    function acceptedMutation(subject) {
        assertNotRotating(subject);
        const master=unlockedMasters.get(subject);
        if(!master)throw coded("VAULT_LOCKED","Vault locked. Unlock it to continue.");
        return master;
    }
    function trackWriteTransaction(subject, transaction) {
        if(!activeWriteTransactions.has(subject))activeWriteTransactions.set(subject,new Set());
        activeWriteTransactions.get(subject).add(transaction);
    }
    function untrackWriteTransaction(subject, transaction) {
        const transactions=activeWriteTransactions.get(subject);transactions?.delete(transaction);if(transactions?.size===0)activeWriteTransactions.delete(subject);
    }

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
            transaction.onabort = () => reject(transaction.error || new Error("Lockstep could not save on this device. Try again."));
        });
    }

    // One connection is opened lazily and shared by every operation instead of opening and closing the
    // database for each read and write. It is dropped (and reopened on next use) if the browser closes it
    // or another tab needs to upgrade the database.
    let sharedDatabase = null;
    function openDatabase() {
        sharedDatabase ||= new Promise((resolve, reject) => {
            const request = indexedDB.open(DB_NAME, DB_VERSION);
            request.onupgradeneeded = () => {
                const database = request.result;
                if (!database.objectStoreNames.contains("keys")) database.createObjectStore("keys", { keyPath: "id" });
                if (!database.objectStoreNames.contains("entries")) database.createObjectStore("entries", { keyPath: "storageId" });
                if (!database.objectStoreNames.contains("outbox")) database.createObjectStore("outbox", { keyPath: "mutationId" });
                for (const name of ["keys", "entries", "outbox"]) {
                    const store = request.transaction.objectStore(name);
                    if (!store.indexNames.contains("bySubject")) store.createIndex("bySubject", "subject");
                }
            };
            request.onsuccess = () => {
                const database = request.result;
                database.onversionchange = () => { database.close(); sharedDatabase = null; };
                database.onclose = () => { sharedDatabase = null; };
                resolve(database);
            };
            request.onerror = () => { sharedDatabase = null; reject(request.error); };
        });
        return sharedDatabase;
    }
    // Operations used to close their own connection; the shared connection now stays open.
    function releaseDatabase() { /* intentionally empty */ }

    async function subjectRecords(storeName, subject) {
        const database = await openDatabase();
        const transaction = database.transaction(storeName, "readonly");
        const result = await requestResult(transaction.objectStore(storeName).index("bySubject").getAll(IDBKeyRange.only(subject)));
        await transactionDone(transaction);
        releaseDatabase(database);
        return result;
    }

    async function get(storeName, key) {
        const database = await openDatabase();
        const transaction = database.transaction(storeName, "readonly");
        const result = await requestResult(transaction.objectStore(storeName).get(key));
        await transactionDone(transaction);
        releaseDatabase(database);
        return result;
    }

    async function put(storeName, value) {
        const database = await openDatabase();
        const transaction = database.transaction(storeName, "readwrite");
        transaction.objectStore(storeName).put(value);
        await transactionDone(transaction);
        releaseDatabase(database);
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

    const NEW_PASSPHRASE_MIN_LENGTH = 12;
    // New or changed passphrases need at least 12 characters. Existing shorter ones keep unlocking.
    function requireNewPassphrase(passphrase) {
        if (typeof passphrase !== "string" || passphrase.length < NEW_PASSPHRASE_MIN_LENGTH || passphrase.length > 128) {
            throw new Error(`Passphrase must contain ${NEW_PASSPHRASE_MIN_LENGTH} to 128 characters.`);
        }
    }

    function requirePassphrase(passphrase) {
        if (typeof passphrase !== "string" || passphrase.length < 4 || passphrase.length > 128) {
            throw new Error("Passphrase must contain 4 to 128 characters.");
        }
    }

    // The passphrase-derived key that encrypts the vault master key: PBKDF2-SHA-256 (600,000 rounds), or
    // Argon2id (memory-hard; 64 MiB, 3 passes) once the server announces "argon2idWrapping". Every
    // wrapped key records how it was made, so both kinds keep opening.
    const PBKDF2_WRAPPING = "PBKDF2-SHA256/AES-256-GCM";
    const ARGON2ID_WRAPPING = "ARGON2ID-V13/AES-256-GCM";
    const ARGON2ID_PARAMETERS = { iterations: 3, memoryKiB: 65536, parallelism: 1 };
    let argon2idWrapping = false;
    function setArgon2idWrapping(enabled) { argon2idWrapping = Boolean(enabled); }
    async function argon2id() {
        if (!globalThis.LockstepArgon2id && typeof globalThis.LockstepLoadArgon2id === "function") await globalThis.LockstepLoadArgon2id();
        if (!globalThis.LockstepArgon2id) throw new Error("This browser cannot open your vault. Update it and try again.");
        return globalThis.LockstepArgon2id;
    }
    function useArgon2id(passphrase) {
        // Argon2id needs at least 8 bytes of passphrase; shorter, older passphrases stay on PBKDF2.
        return argon2idWrapping && encoder.encode(passphrase).length >= 8
            && (Boolean(globalThis.LockstepArgon2id) || typeof globalThis.LockstepLoadArgon2id === "function");
    }
    function wrappingParameters(record) {
        if(typeof record.salt!=="string"||record.salt.length!==24)throw coded("INVALID_WRAPPING_PARAMETERS","The encryption settings are damaged or unsupported.");
        return { wrapping: record.wrapping, salt: base64ToBytes(record.salt), iterations: record.iterations,
            memoryKiB: record.memoryKiB, parallelism: record.parallelism };
    }

    async function wrappingKey(passphrase, parameters, usage) {
        // Local records can be damaged or imported. Bound all KDF paths, not only backup JSON,
        // before loading WASM or handing work to WebCrypto. Never reduce valid vault settings.
        const sane = parameters.salt?.byteLength===16 && Number.isInteger(parameters.iterations) &&
            (parameters.wrapping===ARGON2ID_WRAPPING
                ? parameters.iterations>=1&&parameters.iterations<=10&&Number.isInteger(parameters.memoryKiB)&&parameters.memoryKiB>=8192&&parameters.memoryKiB<=262144&&Number.isInteger(parameters.parallelism)&&parameters.parallelism>=1&&parameters.parallelism<=4
                : parameters.wrapping===PBKDF2_WRAPPING&&parameters.iterations>=100000&&parameters.iterations<=2000000);
        if(!sane)throw coded("INVALID_WRAPPING_PARAMETERS","The encryption settings are damaged or unsupported.");
        if (parameters.wrapping === ARGON2ID_WRAPPING) {
            const raw = await (await argon2id()).hash({ password: encoder.encode(passphrase), salt: parameters.salt,
                passes: parameters.iterations, memorySize: parameters.memoryKiB, parallelism: parameters.parallelism, tagLength: 32 });
            try { return await crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, false, usage); }
            finally { raw.fill(0); }
        }
        const material = await crypto.subtle.importKey("raw", encoder.encode(passphrase), "PBKDF2", false, ["deriveKey"]);
        return crypto.subtle.deriveKey(
            { name: "PBKDF2", hash: "SHA-256", salt: parameters.salt, iterations: parameters.iterations }, material,
            { name: "AES-GCM", length: 256 }, false, usage
        );
    }

    async function wrappedMasterRecord(subject, raw, currentVersion, passphrase, createdAt = Date.now()) {
        requirePassphrase(passphrase);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const parameters = useArgon2id(passphrase)
            ? { wrapping: ARGON2ID_WRAPPING, salt, ...ARGON2ID_PARAMETERS }
            : { wrapping: PBKDF2_WRAPPING, salt, iterations: WRAP_ITERATIONS };
        const key = await wrappingKey(passphrase, parameters, ["encrypt"]);
        const wrapped = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: encoder.encode(`lockstep:master-key:${subject}`), tagLength: 128 },
            key, raw
        );
        return {
            id: masterKeyId(subject), subject, currentVersion, createdAt, wrappedAt: Date.now(),
            wrapping: parameters.wrapping, iterations: parameters.iterations,
            ...(parameters.wrapping === ARGON2ID_WRAPPING ? { memoryKiB: parameters.memoryKiB, parallelism: parameters.parallelism } : {}),
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
        if (existing) throw new Error("Vault locked. Unlock it to continue.");
        const legacy = await get("keys", keyId(subject, 1));
        if (legacy || create) throw new Error("Protect this vault with a Lockstep passphrase before using it.");
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
        // Derived keys are remembered on the unlocked master (dropped when the vault locks or the master changes).
        master.versionKeys ||= new Map();
        let derived = master.versionKeys.get(version);
        if (!derived) {
            derived = deriveVersionKey(master, subject, version);
            master.versionKeys.set(version, derived);
            derived.catch(() => master.versionKeys.delete(version));
        }
        // The current key version comes only from the wrapped key (the server's is authoritative). Seeing an
        // account with a newer version means the recovery key was rotated on another device and this device does
        // not have the new key yet: raising the version here would label new accounts with the new version while
        // encrypting them with the old key, so no other device could open them.
        return { id: keyId(subject, version), subject, version, key: await derived, createdAt: Date.now() };
    }

    async function configurePassphrase(subject, passphrase, isNewPassphrase = true) {
        assertNotRotating(subject);
        const ticket=operationTicket(subject,false);
        if (isNewPassphrase) requireNewPassphrase(passphrase); else requirePassphrase(passphrase);
        const expected=await masterState(subject),persisted=expected.record;
        let master = unlockedMasters.get(subject);
        if (!master && persisted?.wrappedMasterKey) {
            // A previous setup attempt may have wrapped the local master key before
            // the server-side lock configuration was saved. Treat the same passphrase
            // as an idempotent setup retry instead of permanently stranding the vault.
            try {
                await unlock(subject, passphrase);
                master = unlockedMasters.get(subject);
            } catch(error) {
                if(error?.code==="VAULT_LOCKED")throw error;
                throw new Error("This browser already has a protected vault. Enter its existing passphrase to continue setup.");
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
        const wrapped=await wrappedMasterRecord(subject, raw, master.currentVersion, passphrase, master.createdAt);assertOperationTicket(subject,ticket,false);
        // Not on the server yet: remember which server revision this change is based on, so it is uploaded
        // only if the server still has that revision (otherwise the server's key wins; see synchronizeWrappedKey).
        markPendingUpload(wrapped, persisted, subject);
        const database = await openDatabase();
        assertOperationTicket(subject,ticket,false);
        const transaction = database.transaction("keys", "readwrite");
        trackWriteTransaction(subject,transaction);
        try{
            const store = transaction.objectStore("keys");
            const [current,state]=await Promise.all([requestResult(store.get(masterKeyId(subject))),requestResult(store.get(localStateId(subject)))]);
            if((state?.erasureGeneration||0)!==expected.erasureGeneration || current?.wrappedMasterKey!==persisted?.wrappedMasterKey || current?.raw!==persisted?.raw || current?.currentVersion!==persisted?.currentVersion){
                transaction.abort();throw coded("VAULT_LOCKED","This vault was removed or changed during passphrase setup.");
            }
            assertOperationTicket(subject,ticket,false);store.put(wrapped);
            for (const record of await requestResult(store.index("bySubject").getAll(IDBKeyRange.only(subject)))) {
                // Old per-version keys go; the saved sync cursor and tab session keys are not key material for the vault.
                if (record.subject === subject && record.id !== masterKeyId(subject) && !record.localState && !record.syncCursor && !record.sessionWrap && !record.parkedChange && !record.retiredMaster) store.delete(record.id);
            }
            await transactionDone(transaction);assertOperationTicket(subject,ticket,false);
        }finally{untrackWriteTransaction(subject,transaction);releaseDatabase(database);}
        master.wrappedMasterKey = wrapped.wrappedMasterKey;
        unlockedMasters.set(subject, master);
        return true;
    }

    async function unlock(subject, passphrase, expectedGeneration = lockGeneration(subject)) {
        assertOperationTicket(subject,expectedGeneration,false);
        requirePassphrase(passphrase);
        const expected=await masterState(subject),record=expected.record;
        if (!record?.wrappedMasterKey) {
            if (await keyState(subject) === "legacy") {
                await configurePassphrase(subject, passphrase, false);
                const migrated=unlockedMasters.get(subject);
                await assertMasterState(subject,{record:{wrappedMasterKey:migrated?.wrappedMasterKey,currentVersion:migrated?.currentVersion},erasureGeneration:expected.erasureGeneration},expectedGeneration);
                return true;
            }
            throw coded("KEY_MISSING", "This device does not have your vault key. Restore it with your recovery key.");
        }
        try {
            const key = await wrappingKey(passphrase, wrappingParameters(record), ["decrypt"]);
            const raw = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: base64ToBytes(record.iv), additionalData: encoder.encode(`lockstep:master-key:${subject}`), tagLength: 128 },
                key, base64ToBytes(record.wrappedMasterKey)
            ));
            const imported=await importMaster(raw);
            await assertMasterState(subject,expected,expectedGeneration);
            unlockedMasters.set(subject, { raw: bytesToBase64(raw), key: imported, currentVersion: record.currentVersion, createdAt: record.createdAt,
                wrappedMasterKey: record.wrappedMasterKey });
            return true;
        } catch(error) { if(error?.code==="VAULT_LOCKED")throw error;throw coded("WRONG_PASSKEY", "Incorrect passphrase."); }
    }

    // True when the passphrase unwraps the given wrapped vault key (for example the copy on the server).
    // Nothing is stored or unlocked; used to tell "wrong passphrase" from "passphrase changed on another device".
    async function passkeyOpensWrappedKey(subject, wrapped, passphrase) {
        if (!wrapped?.wrappedMasterKey || typeof passphrase !== "string" || !passphrase) return false;
        try {
            const key = await wrappingKey(passphrase, wrappingParameters(wrapped), ["decrypt"]);
            await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: base64ToBytes(wrapped.iv), additionalData: encoder.encode(`lockstep:master-key:${subject}`), tagLength: 128 },
                key, base64ToBytes(wrapped.wrappedMasterKey));
            return true;
        } catch { return false; }
    }

    function coded(code, message) { const error = new Error(message); error.code = code; return error; }

    // Password-protected backup: the same "otpauth://" text, encrypted with AES-256-GCM under a key derived
    // from a backup password the user chooses (Argon2id when this browser can load it, otherwise PBKDF2).
    // The file is JSON and records how it was made, so either app can open it with the password.
    const BACKUP_FORMAT = "lockstep-encrypted-backup";
    const BACKUP_AAD = "lockstep:backup:v1";
    async function encryptBackup(text, password) {
        if (typeof password !== "string" || password.length < NEW_PASSPHRASE_MIN_LENGTH || password.length > 128) {
            throw new Error(`The backup password must contain ${NEW_PASSPHRASE_MIN_LENGTH} to 128 characters.`);
        }
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        let canUseArgon2id = Boolean(globalThis.LockstepArgon2id);
        if (!canUseArgon2id && typeof globalThis.LockstepLoadArgon2id === "function") {
            canUseArgon2id = await globalThis.LockstepLoadArgon2id().then(() => Boolean(globalThis.LockstepArgon2id), () => false);
        }
        const parameters = canUseArgon2id
            ? { wrapping: ARGON2ID_WRAPPING, salt, ...ARGON2ID_PARAMETERS }
            : { wrapping: PBKDF2_WRAPPING, salt, iterations: WRAP_ITERATIONS };
        const key = await wrappingKey(password, parameters, ["encrypt"]);
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: encoder.encode(BACKUP_AAD), tagLength: 128 }, key, encoder.encode(text));
        return JSON.stringify({ format: BACKUP_FORMAT, version: 1, wrapping: parameters.wrapping, iterations: parameters.iterations,
            ...(parameters.wrapping === ARGON2ID_WRAPPING ? { memoryKiB: parameters.memoryKiB, parallelism: parameters.parallelism } : {}),
            salt: bytesToBase64(salt), iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) }, null, 1) + "\n";
    }

    function isEncryptedBackup(text) {
        if (typeof text !== "string" || !text.trimStart().startsWith("{")) return false;
        try { return JSON.parse(text)?.format === BACKUP_FORMAT; } catch { return false; }
    }

    async function decryptBackup(text, password) {
        let backup;
        try { backup = JSON.parse(text); } catch { throw new Error("This backup file is damaged."); }
        if (backup?.format !== BACKUP_FORMAT || backup.version !== 1) throw new Error("This backup was made by a newer version of Lockstep.");
        const argon = backup.wrapping === ARGON2ID_WRAPPING;
        // Refuse settings no Lockstep app writes, so a crafted file cannot make the browser work for minutes.
        const sane = argon
            ? backup.iterations >= 1 && backup.iterations <= 10 && backup.memoryKiB >= 8192 && backup.memoryKiB <= 262144 && backup.parallelism >= 1 && backup.parallelism <= 4
            : backup.wrapping === PBKDF2_WRAPPING && backup.iterations >= 100000 && backup.iterations <= 2000000;
        if (!sane || typeof backup.salt !== "string" || typeof backup.iv !== "string" || typeof backup.ciphertext !== "string") {
            throw new Error("This backup file is damaged.");
        }
        if (typeof password !== "string" || !password) throw coded("WRONG_BACKUP_PASSWORD", "Enter the backup password.");
        const key = await wrappingKey(password, wrappingParameters(backup), ["decrypt"]);
        try {
            const plain = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: base64ToBytes(backup.iv), additionalData: encoder.encode(BACKUP_AAD), tagLength: 128 },
                key, base64ToBytes(backup.ciphertext));
            return new TextDecoder().decode(plain);
        } catch { throw coded("WRONG_BACKUP_PASSWORD", "Wrong backup password."); }
    }

    // True when the passphrase opens this device's wrapped vault key (checked locally; nothing is stored).
    // Used to confirm it is the vault's owner before an export.
    // A vault from before passphrases were required has no wrapped key and nothing to check against.
    async function checkPassphrase(subject, passphrase) {
        const wrapped = await exportWrappedKey(subject);
        if (!wrapped?.wrappedMasterKey) return true;
        return passkeyOpensWrappedKey(subject, wrapped, passphrase);
    }

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
            wrapping: record.wrapping, iterations: record.iterations, salt: record.salt, iv: record.iv, wrappedMasterKey: record.wrappedMasterKey,
            ...(record.memoryKiB ? { memoryKiB: record.memoryKiB, parallelism: record.parallelism } : {}) };
    }

    function markPendingUpload(record, previous, subject) {
        const base = previous?.wrappedMasterKey ? previous.serverRevision : undefined;
        record.serverRevision = Number.isInteger(base) ? base : (knownRevisions.has(subject) ? knownRevisions.get(subject) : null);
        record.pendingUpload = true;
        return record;
    }

    // The wrapped key on the server is authoritative. With a server revision (current servers), this device
    // adopts the server's key whenever it differs, except for a local change not uploaded yet that is based
    // on the server's current revision (it is uploaded next, with that revision as the expected one). Device
    // clocks are never compared. Older servers send no revision; then the previous timestamp rule applies.
    async function synchronizeWrappedKey(subject, remote, revision = undefined) {
        const hasRevision = Number.isInteger(revision);
        if (hasRevision && !(knownRevisions.get(subject) > revision)) knownRevisions.set(subject, revision);
        if (!remote?.wrappedMasterKey) return false;
        const local = await get("keys", masterKeyId(subject));
        if (hasRevision) {
            // A response older than what this device already knows (it was in flight during a change) is ignored.
            if (Number.isInteger(local?.serverRevision) && revision < local.serverRevision) return false;
            if (local?.wrappedMasterKey === remote.wrappedMasterKey) {
                if (local.serverRevision !== revision || local.pendingUpload) {
                    local.serverRevision = revision; delete local.pendingUpload;
                    await put("keys", local);
                }
                return false;
            }
            if (local?.wrappedMasterKey && local.pendingUpload && local.serverRevision === revision) return false;
            await retireMasterIfNeeded(subject, local, remote);
            await put("keys", { id: masterKeyId(subject), subject, currentVersion: remote.currentVersion, createdAt: remote.createdAt,
                wrappedAt: Number(remote.wrappedAt || remote.createdAt || 0), wrapping: remote.wrapping, iterations: remote.iterations,
                ...(remote.memoryKiB ? { memoryKiB: remote.memoryKiB, parallelism: remote.parallelism } : {}),
                salt: remote.salt, iv: remote.iv, wrappedMasterKey: remote.wrappedMasterKey, serverRevision: revision });
            lock(subject);
            await forgetSyncCursor(subject);
            return true;
        }
        const remoteWrappedAt = Number(remote.wrappedAt || remote.createdAt || 0);
        const localWrappedAt = Number(local?.wrappedAt || local?.createdAt || 0);
        if (local?.wrappedMasterKey && remoteWrappedAt <= localWrappedAt) return false;
        await retireMasterIfNeeded(subject, local, remote);
        await put("keys", { id: masterKeyId(subject), subject, currentVersion: remote.currentVersion, createdAt: remote.createdAt,
            wrappedAt: remoteWrappedAt, wrapping: remote.wrapping, iterations: remote.iterations,
            ...(remote.memoryKiB ? { memoryKiB: remote.memoryKiB, parallelism: remote.parallelism } : {}),
            salt: remote.salt, iv: remote.iv, wrappedMasterKey: remote.wrappedMasterKey });
        lock(subject);
        await forgetSyncCursor(subject);
        return true;
    }

    // The recovery key was rotated on another device while this one still has accounts added offline with the
    // old key (not on the server yet). Their only key would be lost when this device takes the new one, so the
    // old wrapped key (protected by the passphrase in use at the time) is kept until those accounts have been
    // re-encrypted with the new key (rescueStrandedEntries, after the next unlock). A passphrase change keeps
    // the same key version and never keeps the old wrapper.
    function retiredId(subject, version) { return `${subject}:retired-master:${version}`; }
    async function retireMasterIfNeeded(subject, local, remote) {
        if (!local?.wrappedMasterKey || !(Number(remote?.currentVersion) > Number(local.currentVersion))) return;
        const version = local.currentVersion;
        const outbox = (await subjectRecords("outbox", subject)).filter(item => item.subject === subject);
        const parked = await parkedEntryIds(subject);
        const strandedIds = new Set([...outbox.filter(item => item.operation === "PUT" && !item.payload?.baseMutationId).map(item => item.entryId), ...parked]);
        const stranded = (await localEncryptedEntries(subject)).some(entry => strandedIds.has(entry.id) && entry.keyVersion === version);
        if (!stranded) return;
        const { pendingUpload: ignoredPending, serverRevision: ignoredRevision, ...wrapped } = local;
        await put("keys", { ...wrapped, id: retiredId(subject, version), retiredMaster: true });
    }

    // Re-encrypts accounts that were added offline with a recovery key rotated away since (see
    // retireMasterIfNeeded) with the current key, and queues them as new accounts. Needs the vault unlocked and
    // the passphrase that protected the old key (usually the same: a rotation keeps the passphrase). Accounts
    // whose old key cannot be opened stay as they are (listed with an error), and the old key is kept for them.
    async function rescueStrandedEntries(subject, passphrase) {
        if (!unlockedMasters.has(subject)) return 0;
        // Runs like an upload (one at a time with uploads, also across tabs) and stops if the vault is locked.
        const ticket = operationTicket(subject);
        const run = () => rescueNow(subject, passphrase, ticket);
        const previous = outboxFlushes.get(subject) || Promise.resolve();
        const current = previous.catch(() => null).then(() => globalThis.navigator?.locks?.request ? navigator.locks.request(`lockstep-outbox:${subject}`, run) : run());
        outboxFlushes.set(subject, current);
        try { return await current; } finally { if (outboxFlushes.get(subject) === current) outboxFlushes.delete(subject); }
    }
    async function rescueNow(subject, passphrase, ticket) {
        assertOperationTicket(subject, ticket);
        const master = unlockedMasters.get(subject);
        if (!master || typeof passphrase !== "string" || !passphrase) return 0;
        const retired = (await subjectRecords("keys", subject)).filter(record => record.subject === subject && record.retiredMaster);
        if (!retired.length) return 0;
        const parked = await parkedEntryIds(subject);
        const outbox = (await subjectRecords("outbox", subject)).filter(item => item.subject === subject);
        const strandedIds = new Set([...outbox.filter(item => item.operation === "PUT" && !item.payload?.baseMutationId).map(item => item.entryId), ...parked]);
        const stranded = (await localEncryptedEntries(subject)).filter(entry => strandedIds.has(entry.id) && entry.keyVersion < master.currentVersion);
        const current = await keyFor(subject, master.currentVersion);
        let rescued = 0;
        for (const record of retired) {
            const mine = stranded.filter(entry => entry.keyVersion === record.currentVersion);
            let old;
            try {
                const key = await wrappingKey(passphrase, wrappingParameters(record), ["decrypt"]);
                const raw = new Uint8Array(await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: base64ToBytes(record.iv), additionalData: encoder.encode(`lockstep:master-key:${subject}`), tagLength: 128 },
                    key, base64ToBytes(record.wrappedMasterKey)));
                old = { raw: bytesToBase64(raw), key: await importMaster(raw) };
            } catch { if (mine.length) continue; old = null; }
            let left = 0;
            for (const entry of mine) {
                try {
                    const oldKey = await deriveVersionKey(old, subject, entry.keyVersion);
                    const secret = decoder.decode(await crypto.subtle.decrypt(
                        { name: "AES-GCM", iv: base64ToBytes(entry.secretIv), additionalData: associatedData(subject, entry.id, entry.keyVersion), tagLength: 128 },
                        oldKey, base64ToBytes(entry.encryptedSecret)));
                    let labels = { issuer: entry.issuer, accountName: entry.accountName };
                    if (entry.encryptedLabel && entry.labelIv) {
                        labels = JSON.parse(decoder.decode(await crypto.subtle.decrypt(
                            { name: "AES-GCM", iv: base64ToBytes(entry.labelIv), additionalData: labelData(subject, entry.id, entry.keyVersion), tagLength: 128 },
                            oldKey, base64ToBytes(entry.encryptedLabel))));
                    }
                    const encrypted = await encryptSecret(subject, entry.id, secret, current);
                    const sealed = await sealLabels(subject, entry.id, labels, current, Boolean(entry.encryptedLabel));
                    const updated = { ...entry, ...encrypted, ...sealed, mutationId: crypto.randomUUID(), baseMutationId: null, updatedAtEpochMillis: Date.now() };
                    delete updated.storageId; delete updated.subject;
                    // One transaction: the re-encrypted account, a fresh upload, and no older upload or "kept locally" mark.
                    assertOperationTicket(subject, ticket);
                    const database = await openDatabase();
                    const transaction = database.transaction(["entries", "outbox", "keys"], "readwrite");
                    trackWriteTransaction(subject, transaction);
                    const queue = transaction.objectStore("outbox");
                    for (const item of outbox.filter(item => item.entryId === entry.id)) queue.delete(item.mutationId);
                    transaction.objectStore("keys").delete(parkedId(subject, entry.id));
                    transaction.objectStore("entries").put({ ...updated, subject, storageId: storageId(subject, entry.id) });
                    const sequence = await advanceLocalState(transaction, subject, true);
                    queue.put({ mutationId: updated.mutationId, subject, entryId: entry.id, operation: "PUT", payload: wireEntry(updated), createdAt: Date.now(), sequence, attempts: 0 });
                    try { await transactionDone(transaction); } finally { untrackWriteTransaction(subject, transaction); }
                    assertOperationTicket(subject, ticket);
                    rescued++;
                } catch (error) { if (error?.code === "VAULT_LOCKED") throw error; left++; }
            }
            if (!left) {
                const database = await openDatabase();
                const transaction = database.transaction("keys", "readwrite");
                transaction.objectStore("keys").delete(record.id);
                await transactionDone(transaction);
            }
        }
        return rescued;
    }

    // A user-requested rotation may encounter a local revision ahead of the server (for example after
    // a restore). Never downgrade key material just because the revision is lower: prove the server
    // and persisted local wrappers contain the same master before repairing only its metadata.
    // The server's vault was replaced outside Lockstep: its revision is lower than the one this device saved
    // and its key is different (for example data deleted or restored in the Firebase console, then a new vault
    // created). A slow, older response cannot cause this when the caller has just read the server.
    async function serverVaultReplaced(subject, remote, revision) {
        const local = await get("keys", masterKeyId(subject));
        return Number.isInteger(revision) && Number.isInteger(local?.serverRevision) && revision < local.serverRevision
            && Boolean(remote?.wrappedMasterKey) && Boolean(local?.wrappedMasterKey) && local.wrappedMasterKey !== remote.wrappedMasterKey;
    }

    // Takes the server's vault key in place of this device's older one, but only when nothing would be lost:
    // no change waiting to upload, and no account on this device that the server does not have. Otherwise it
    // refuses with VAULT_REPLACED (the device keeps its own key, so those accounts can still be exported).
    // {force: true} (the user chose the server's vault) removes this device's copy of the older vault first.
    async function adoptReplacedServerVault(subject, remote, revision, serverEntryIds, { force = false } = {}) {
        if (force) {
            await clearSubject(subject);
        } else {
            const local = await get("keys", masterKeyId(subject));
            const pending = local?.pendingUpload || await pendingCount(subject);
            const onServer = new Set(serverEntryIds);
            const onlyHere = (await localEncryptedEntries(subject)).filter((entry) => !onServer.has(entry.id)).length;
            if (pending || onlyHere) {
                const what = [onlyHere ? `${onlyHere} account${onlyHere === 1 ? "" : "s"}` : "", pending ? "changes that were never uploaded" : ""].filter(Boolean).join(" and ");
                const error = coded("VAULT_REPLACED", `The server's vault was replaced, but this device still has ${what} from the older vault that the server does not have.`);
                error.onlyHere = onlyHere; error.pending = Boolean(pending);
                throw error;
            }
        }
        await put("keys", { id: masterKeyId(subject), subject, currentVersion: remote.currentVersion, createdAt: remote.createdAt,
            wrappedAt: Number(remote.wrappedAt || remote.createdAt || 0), wrapping: remote.wrapping, iterations: remote.iterations,
            ...(remote.memoryKiB ? { memoryKiB: remote.memoryKiB, parallelism: remote.parallelism } : {}),
            salt: remote.salt, iv: remote.iv, wrappedMasterKey: remote.wrappedMasterKey, serverRevision: revision });
        knownRevisions.set(subject, revision);
        unlockedMasters.delete(subject);
        return true;
    }

    async function refreshRotationKey(subject, remote, revision, passphrase) {
        const local = await get("keys", masterKeyId(subject));
        if (!Number.isInteger(revision) || !Number.isInteger(local?.serverRevision) || revision >= local.serverRevision) {
            return synchronizeWrappedKey(subject, remote, revision);
        }
        const master = unlockedMasters.get(subject);
        if (!master) throw coded("VAULT_LOCKED", "Unlock again before rotating the recovery key.");
        if (!remote?.wrappedMasterKey) {
            throw coded("VAULT_STATE_MISMATCH", "The server has no vault key yet. Nothing was changed.");
        }
        if (remote.currentVersion !== local.currentVersion || master.currentVersion !== local.currentVersion) {
            throw coded("VAULT_STATE_MISMATCH", `This device and the server have different vault keys. Rotation stopped to protect your accounts; lock and unlock Lockstep, then try again.`);
        }
        let raw, localRaw;
        try {
            // A resumed session may contain an older master with the same numeric version.
            // Verify the persisted local wrapper too; memory alone is not proof of a key mismatch.
            const localKey = await wrappingKey(passphrase, wrappingParameters(local), ["decrypt"]);
            localRaw = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: base64ToBytes(local.iv), additionalData: encoder.encode(`lockstep:master-key:${subject}`), tagLength: 128 },
                localKey, base64ToBytes(local.wrappedMasterKey)));
            const key = await wrappingKey(passphrase, wrappingParameters(remote), ["decrypt"]);
            raw = new Uint8Array(await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: base64ToBytes(remote.iv), additionalData: encoder.encode(`lockstep:master-key:${subject}`), tagLength: 128 },
                key, base64ToBytes(remote.wrappedMasterKey)));
        } catch {
            throw coded("VAULT_STATE_MISMATCH", "Your passphrase does not open the current vault key. Lock and unlock Lockstep with your current passphrase, then try again.");
        }
        if (raw.length !== 32 || localRaw.length !== 32 || bytesToBase64(raw) !== bytesToBase64(localRaw)) {
            throw coded("VAULT_STATE_MISMATCH", "This device and the server have different vault keys. Rotation stopped to protect your accounts; lock and unlock Lockstep, then try again.");
        }
        const verifiedMaster = { raw: bytesToBase64(localRaw), key: await importMaster(localRaw),
            currentVersion: local.currentVersion, createdAt: local.createdAt, wrappedMasterKey: remote.wrappedMasterKey };
        if (verifiedMaster.raw !== master.raw && await pendingCount(subject)) {
            throw coded("VAULT_STATE_MISMATCH", "This device has changes that have not synced yet. Rotation stopped to keep them; try again once they sync.");
        }
        const current = await get("keys", masterKeyId(subject));
        if (unlockedMasters.get(subject) !== master || current?.wrappedMasterKey !== local.wrappedMasterKey ||
                current.currentVersion !== local.currentVersion || current.serverRevision !== local.serverRevision ||
                Boolean(current.pendingUpload) !== Boolean(local.pendingUpload)) {
            throw coded("VAULT_STATE_MISMATCH", "The vault changed during verification. Try again.");
        }
        await put("keys", { id: masterKeyId(subject), subject, currentVersion: remote.currentVersion, createdAt: remote.createdAt,
            wrappedAt: Number(remote.wrappedAt || remote.createdAt || 0), wrapping: remote.wrapping, iterations: remote.iterations,
            ...(remote.memoryKiB ? { memoryKiB: remote.memoryKiB, parallelism: remote.parallelism } : {}),
            salt: remote.salt, iv: remote.iv, wrappedMasterKey: remote.wrappedMasterKey, serverRevision: revision });
        knownRevisions.set(subject, revision);
        if (unlockedMasters.get(subject) !== master) throw coded("VAULT_LOCKED", "Vault locked. Unlock it to continue.");
        unlockedMasters.set(subject, verifiedMaster);
        return false; // identical persisted master: keep the vault unlocked with the verified key
    }

    // Re-protect a PBKDF2 vault with Argon2id after unlock, retaining its master and passphrase.
    // The new wrapper is saved on the server with the next pending upload.
    async function upgradeWrapping(subject, passphrase) {
        const master = unlockedMasters.get(subject);
        const record = await get("keys", masterKeyId(subject));
        if (!master || !record?.wrappedMasterKey || record.wrapping === ARGON2ID_WRAPPING || !useArgon2id(passphrase)) return false;
        const upgraded = await wrappedMasterRecord(subject, base64ToBytes(master.raw), record.currentVersion, passphrase, record.createdAt);
        if (unlockedMasters.get(subject) !== master) return false; // locked meanwhile
        await put("keys", markPendingUpload(upgraded, record, subject));
        master.wrappedMasterKey = upgraded.wrappedMasterKey;
        return true;
    }

    // True when upgradeWrapping would re-protect this unlocked vault with Argon2id (the server announces it, the
    // passphrase is long enough and the stored key still uses PBKDF2).
    async function needsWrappingUpgrade(subject, passphrase) {
        if (!unlockedMasters.has(subject) || !useArgon2id(passphrase)) return false;
        const record = await get("keys", masterKeyId(subject));
        return Boolean(record?.wrappedMasterKey) && record.wrapping !== ARGON2ID_WRAPPING;
    }

    // A local passphrase change or recovery-key import not yet saved on the server, with the revision to expect.
    async function pendingWrappedKeyUpload(subject) {
        const local = await get("keys", masterKeyId(subject));
        if (!local?.wrappedMasterKey || !local.pendingUpload) return null;
        return { wrappedKey: await exportWrappedKey(subject), expectedRevision: Number.isInteger(local.serverRevision) ? local.serverRevision : null };
    }

    // The server revision a lock change should expect: the one this device's key is based on.
    async function expectedRevision(subject) {
        const local = await get("keys", masterKeyId(subject));
        if (Number.isInteger(local?.serverRevision)) return local.serverRevision;
        return knownRevisions.has(subject) ? knownRevisions.get(subject) : null;
    }

    // Called after the server accepted this device's wrapped key (lock save, restore, rotation).
    async function markWrappedKeySynced(subject, revision, acknowledged) {
        if (!Number.isInteger(revision) || !acknowledged?.wrappedMasterKey) return false;
        const database = await openDatabase();
        const transaction = database.transaction("keys", "readwrite");
        const store = transaction.objectStore("keys");
        const local = await requestResult(store.get(masterKeyId(subject)));
        const matches = local?.wrappedMasterKey === acknowledged.wrappedMasterKey
            && local.currentVersion === acknowledged.currentVersion
            && !(local.serverRevision > revision);
        if (matches) {
            local.serverRevision = revision; delete local.pendingUpload; store.put(local);
        }
        await transactionDone(transaction);
        if (matches) knownRevisions.set(subject, Math.max(knownRevisions.get(subject) || 0, revision));
        return matches;
    }

    function lock(subject) {
        endRotation(subject, rotatingSubjects.get(subject));
        unlockedMasters.delete(subject);lockGenerations.set(subject,lockGeneration(subject)+1);
        for(const transaction of activeWriteTransactions.get(subject)||[]){try{transaction.abort();}catch{/* already completed */}}
        activeWriteTransactions.delete(subject);
    }
    function isUnlocked(subject) { return unlockedMasters.has(subject); }

    // Keeps an unlocked vault open across a page reload in the same tab. The vault key is stored in
    // sessionStorage only encrypted, with a per-tab AES key that cannot be exported and is kept in IndexedDB,
    // so the readable key never sits in browser storage. Locking or signing out deletes both.
    function sessionWrapId(subject, tabKey) { return `${subject}:session-wrap:${tabKey}`; }
    const SESSION_WRAP_MAX_AGE_MILLIS = 7 * 24 * 60 * 60 * 1000;
    async function exportSessionKey(subject, tabKey, ticket) {
        const master = unlockedMasters.get(subject);
        if (!master || typeof tabKey !== "string" || !tabKey) return null;
        const expected=await masterState(subject);
        await assertMasterState(subject,expected,ticket);
        if(expected.record?.wrappedMasterKey!==master.wrappedMasterKey){lock(subject);throw coded("VAULT_LOCKED","The vault changed while saving its session.");}
        let record = await get("keys", sessionWrapId(subject, tabKey));
        if (!record?.key) {
            const candidate = { id: sessionWrapId(subject, tabKey), subject, sessionWrap: true, createdAt: Date.now(),
                key: await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]) };
            assertOperationTicket(subject,ticket);
            const database=await openDatabase(),transaction=database.transaction("keys","readwrite");
            trackWriteTransaction(subject,transaction);
            try {
                const store=transaction.objectStore("keys");
                const [current,state,existing]=await Promise.all([requestResult(store.get(masterKeyId(subject))),requestResult(store.get(localStateId(subject))),requestResult(store.get(candidate.id))]);
                if(current?.wrappedMasterKey!==expected.record.wrappedMasterKey || (state?.erasureGeneration||0)!==expected.erasureGeneration){
                    transaction.abort();throw coded("VAULT_LOCKED","This vault was removed or changed while saving its session.");
                }
                assertOperationTicket(subject,ticket);
                record=existing?.key?existing:candidate;
                if(!existing?.key)store.put(record);
                await transactionDone(transaction);
            }catch(error){try{transaction.abort()}catch{}assertOperationTicket(subject,ticket);throw error;}
            finally{untrackWriteTransaction(subject,transaction);}
            forgetStaleSessionWraps(subject).catch(() => null);
        }
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const sealed = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: encoder.encode(`lockstep:session:${subject}`), tagLength: 128 },
            record.key, base64ToBytes(master.raw));
        await assertMasterState(subject,expected,ticket);
        return { sealed: bytesToBase64(new Uint8Array(sealed)), iv: bytesToBase64(iv), currentVersion: master.currentVersion, createdAt: master.createdAt,
            wrappedMasterKey: master.wrappedMasterKey };
    }
    async function forgetSessionKey(subject, tabKey) {
        if (typeof tabKey !== "string" || !tabKey) return;
        const database = await openDatabase();
        const transaction = database.transaction("keys", "readwrite");
        transaction.objectStore("keys").delete(sessionWrapId(subject, tabKey));
        await transactionDone(transaction);
    }
    // Keys of tabs closed without locking are removed after a week.
    async function forgetStaleSessionWraps(subject) {
        const now = Date.now();
        const database = await openDatabase();
        const transaction = database.transaction("keys", "readwrite");
        const store = transaction.objectStore("keys");
        for (const record of await requestResult(store.index("bySubject").getAll(IDBKeyRange.only(subject)))) {
            if (record.subject === subject && record.sessionWrap && now - Number(record.createdAt || 0) > SESSION_WRAP_MAX_AGE_MILLIS) store.delete(record.id);
        }
        await transactionDone(transaction);
    }

    async function restoreSessionKey(subject, snapshot, tabKey) {
        const ticket=operationTicket(subject,false);
        if (!Number.isInteger(snapshot?.currentVersion)) return false;
        const expected=await masterState(subject),record=expected.record;
        // A version is not a key identity. Never restore a session saved for a different wrapper.
        // Older snapshots without a binding require one normal passphrase unlock after updating.
        if (!record || Number(record.currentVersion) !== snapshot.currentVersion ||
                !snapshot.wrappedMasterKey || snapshot.wrappedMasterKey !== record.wrappedMasterKey) return false;
        let raw;
        if (snapshot.sealed && snapshot.iv) {
            const wrap = await get("keys", sessionWrapId(subject, tabKey));
            if (!wrap?.key) return false;
            try {
                raw = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: base64ToBytes(snapshot.iv),
                    additionalData: encoder.encode(`lockstep:session:${subject}`), tagLength: 128 }, wrap.key, base64ToBytes(snapshot.sealed)));
            } catch { return false; }
        } else if (snapshot.raw) {
            raw = base64ToBytes(snapshot.raw); // only bound migration snapshots pass the checks above
        } else return false;
        if (raw.byteLength !== 32) return false;
        snapshot = { ...snapshot, raw: bytesToBase64(raw) };
        const imported=await importMaster(raw);
        await assertMasterState(subject,expected,ticket);
        unlockedMasters.set(subject, {
            raw: snapshot.raw,
            key: imported,
            currentVersion: snapshot.currentVersion,
            createdAt: snapshot.createdAt || record.createdAt,
            wrappedMasterKey: record.wrappedMasterKey
        });
        return true;
    }

    // Limits matching what the server accepts (EntryService), checked when an account is added or renamed.
    const MAX_SECRET_LENGTH = 512;
    const MIN_SECRET_LENGTH = 8;
    const MAX_ISSUER_LENGTH = 128;
    const MAX_ACCOUNT_LENGTH = 256;
    // The server accepts at most 2,048 bytes of encrypted names (plaintext plus the 16-byte tag).
    const MAX_LABEL_PLAINTEXT_BYTES = 2000;

    function validateLabels(issuer, accountName) {
        if (!issuer || issuer.length > MAX_ISSUER_LENGTH) throw new Error(`Issuer is required and must be at most ${MAX_ISSUER_LENGTH} characters.`);
        if (!accountName || accountName.length > MAX_ACCOUNT_LENGTH) throw new Error(`Account name is required and must be at most ${MAX_ACCOUNT_LENGTH} characters.`);
        if (encoder.encode(JSON.stringify({ issuer, accountName })).length > MAX_LABEL_PLAINTEXT_BYTES) throw new Error("The issuer and account name are too long together.");
    }

    function validateUuidV4(value, field = "ID") {
        if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value)) {
            throw new Error(field + " must be a UUIDv4.");
        }
    }

    function parseOtpAuthUri(uri) {
        let parsed;
        try { parsed = new URL(uri); } catch { throw new Error("This is not a valid authenticator link."); }
        if (parsed.protocol !== "otpauth:" || parsed.hostname.toLowerCase() !== "totp") {
            throw new Error("Only time-based (TOTP) authenticator codes are supported.");
        }
        const secret = (parsed.searchParams.get("secret") || "").toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
        if (!/^[A-Z2-7]+$/.test(secret)) throw new Error("The secret key can only contain the letters A-Z and the digits 2-7.");
        // Checked before anything is saved: a secret the server would refuse could otherwise sit in the
        // upload queue. Real authenticator secrets are 16 to 128 characters.
        if (secret.length > MAX_SECRET_LENGTH) throw new Error(`The secret key is too long (at most ${MAX_SECRET_LENGTH} characters).`);
        // A secret that short cannot be a real key (and one of a single character gives no key at all, so no
        // code could ever be generated). Authenticator secrets are normally 16 or 32 characters.
        if (secret.length < MIN_SECRET_LENGTH) throw new Error(`The secret key is too short (at least ${MIN_SECRET_LENGTH} characters).`);
        let label;
        try { label = decodeURIComponent(parsed.pathname.replace(/^\//, "")); } catch { throw new Error("The account name in this link is not valid."); }
        const separator = label.indexOf(":");
        const labelIssuer = separator >= 0 ? label.slice(0, separator).trim() : "";
        const accountName = (separator >= 0 ? label.slice(separator + 1) : label).trim();
        const issuer = (parsed.searchParams.get("issuer") || labelIssuer).trim();
        const algorithm = (parsed.searchParams.get("algorithm") || "SHA1").toUpperCase().replace("-", "");
        const digits = Number(parsed.searchParams.get("digits") || 6);
        const periodSeconds = Number(parsed.searchParams.get("period") || 30);
        validateLabels(issuer, accountName);
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

    // Issuer and account name are encrypted too, so the server only stores placeholders for them.
    // They use the entry's key version with their own IV and associated data.
    const LABEL_PLACEHOLDER = "Encrypted";
    // Names are only encrypted once the server has confirmed it stores the encrypted fields (an older
    // server would keep only the placeholders). Entries that already have encrypted names stay encrypted.
    let labelEncryption = false;
    function setLabelEncryption(enabled) { labelEncryption = Boolean(enabled); }
    async function sealLabels(subject, id, labels, keyRecord, alreadyEncrypted = false) {
        return labelEncryption || alreadyEncrypted
            ? encryptLabels(subject, id, labels, keyRecord)
            : { issuer: labels.issuer, accountName: labels.accountName, encryptedLabel: null, labelIv: null };
    }
    function labelData(subject, id, version) { return encoder.encode(`lockstep:v2:label:${subject}:${id}:${version}`); }
    async function encryptLabels(subject, id, labels, keyRecord) {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const ciphertext = await crypto.subtle.encrypt(
            { name: "AES-GCM", iv, additionalData: labelData(subject, id, keyRecord.version), tagLength: 128 },
            keyRecord.key, encoder.encode(JSON.stringify({ issuer: labels.issuer, accountName: labels.accountName })));
        return { issuer: LABEL_PLACEHOLDER, accountName: LABEL_PLACEHOLDER,
            encryptedLabel: bytesToBase64(new Uint8Array(ciphertext)), labelIv: bytesToBase64(iv) };
    }
    async function entryLabels(subject, entry) {
        if (!entry.encryptedLabel || !entry.labelIv) return { issuer: entry.issuer, accountName: entry.accountName };
        try {
            const keyRecord = await keyFor(subject, entry.keyVersion);
            const plaintext = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: base64ToBytes(entry.labelIv), additionalData: labelData(subject, entry.id, entry.keyVersion), tagLength: 128 },
                keyRecord.key, base64ToBytes(entry.encryptedLabel));
            const labels = JSON.parse(decoder.decode(plaintext));
            if (typeof labels?.issuer === "string" && typeof labels?.accountName === "string") return { issuer: labels.issuer, accountName: labels.accountName };
        } catch (error) { if (error?.code === "VAULT_LOCKED") throw error; }
        return { issuer: entry.issuer, accountName: entry.accountName };
    }

    async function decryptSecret(subject, entry) {
        const keyRecord = await keyFor(subject, entry.keyVersion);
        if (!keyRecord) throw new Error(`This account needs recovery key version ${entry.keyVersion}. Restore it with that recovery key.`);
        try {
            const plaintext = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: base64ToBytes(entry.secretIv), additionalData: associatedData(subject, entry.id, entry.keyVersion), tagLength: 128 },
                keyRecord.key,
                base64ToBytes(entry.encryptedSecret)
            );
            return decoder.decode(plaintext);
        } catch {
            throw new Error("This account could not be opened on this device. If every account shows this, restore the vault with your recovery key.");
        }
    }

    function base32Bytes(value) {
        const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        let bits = "", output = [];
        for (const character of value.replace(/=+$/, "").toUpperCase()) {
            const index = alphabet.indexOf(character);
            if (index < 0) throw new Error("The secret key can only contain the letters A-Z and the digits 2-7.");
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
        return (await subjectRecords("entries", subject)).filter(entry => entry.subject === subject).sort((a, b) => a.createdAtEpochMillis - b.createdAtEpochMillis);
    }

    function wireEntry(entry) {
        const { storageId: ignoredStorageId, subject: ignoredSubject, ...wire } = entry;
        return wire;
    }

    async function publicEntry(subject, entry, now = Date.now()) {
        const secret = await decryptSecret(subject, entry);
        const generated = await totp(secret, entry.algorithm, entry.digits, entry.periodSeconds, now);
        return { ...wireEntry(entry), ...(await entryLabels(subject, entry)), ...generated, period: entry.periodSeconds, serverEpochMillis: now, validForMillis: generated.validUntilEpochMillis - now };
    }

    // An account that cannot be opened (damaged on the server, or encrypted with a recovery key this device
    // does not have) is listed with an error instead of a code, so it never hides the healthy accounts. It is
    // never deleted here: it may still open after restoring the right recovery key.
    async function brokenEntry(subject, entry, error) {
        if (error?.code === "VAULT_LOCKED") throw error;
        let labels;
        try { labels = await entryLabels(subject, entry); } catch (labelError) { if (labelError?.code === "VAULT_LOCKED") throw labelError; labels = { issuer: entry.issuer, accountName: entry.accountName }; }
        return { ...wireEntry(entry), ...labels, code: null, validUntilEpochMillis: null, secondsRemaining: null, period: entry.periodSeconds,
            error: error?.message || "This account could not be opened." };
    }

    async function listEntries(subject) {
        const ticket = operationTicket(subject);
        const now = Date.now();
        const entries = await localEncryptedEntries(subject);
        const keyRecords = await subjectRecords("keys", subject);
        const parked = new Set(keyRecords.filter(record => record.parkedChange).map(record => record.entryId));
        // Prepare each key version once, then decrypt and generate all codes in parallel (order is kept).
        for (const version of new Set(entries.map(entry => entry.keyVersion))) {
            try { await keyFor(subject, version); } catch (error) { if (error?.code === "VAULT_LOCKED" || /Vault locked/.test(error?.message)) throw error; }
        }
        const listed = await Promise.all(entries.map(entry => publicEntry(subject, entry, now).catch(error => brokenEntry(subject, entry, error))));
        // localOnly: the server refused this account; it exists on this device only (see setAside).
        const reasons = new Map(keyRecords.filter(record => record.parkedChange).map(record => [record.entryId, record.code]));
        const newUploads = new Set((await subjectRecords("outbox", subject)).filter(item => item.subject === subject && item.operation === "PUT" && !item.payload?.baseMutationId).map(item => item.entryId));
        const masterVersion = unlockedMasters.get(subject)?.currentVersion;
        assertOperationTicket(subject, ticket);
        return listed.map(entry => {
            // Added offline with a recovery key rotated away since (see rescueStrandedEntries).
            const stranded = Number.isInteger(masterVersion) && entry.keyVersion < masterVersion && (parked.has(entry.id) || newUploads.has(entry.id));
            if (!parked.has(entry.id) && !stranded) return entry;
            // needsOldPassphrase: it can only be re-encrypted with the passphrase that protected the old key, which
            // differs from the current one. canRetry: uploading it again as it is can succeed.
            const needsOldPassphrase = stranded && Boolean(entry.error);
            return { ...entry, localOnly: true, needsOldPassphrase, canRetry: !stranded && reasons.get(entry.id) !== "STALE_KEY",
                ...(needsOldPassphrase ? { error: "Added offline before your recovery key was rotated. Open it with the passphrase you used then." } : {}) };
        });
    }

    // Queues an account kept on this device only for upload again (for example after removing others to get
    // under the account limit). Returns false when it is not kept locally.
    async function currentCode(subject, id) {
        const ticket = operationTicket(subject);
        const entry = await get("entries", storageId(subject, id));
        if (!entry) throw new Error("This account no longer exists.");
        const result = await publicEntry(subject, entry);
        assertOperationTicket(subject, ticket);
        return result;
    }

    async function retryLocalOnly(subject, id) {
        acceptedMutation(subject);
        if (!(await parkedEntryIds(subject)).has(id)) return false;
        const entry = await get("entries", storageId(subject, id));
        if (!entry) return false;
        const updated = { ...entry, mutationId: crypto.randomUUID(), baseMutationId: null, updatedAtEpochMillis: Date.now() };
        await writeEntryAndOutbox(subject, updated, "PUT", null);
        const database = await openDatabase();
        const transaction = database.transaction("keys", "readwrite");
        transaction.objectStore("keys").delete(parkedId(subject, id));
        await transactionDone(transaction);
        return true;
    }

    async function writeEntryAndOutbox(subject, entry, operation = "PUT", ticket = operationTicket(subject)) {
        assertNotRotating(subject);
        if(ticket!==null)assertOperationTicket(subject,ticket);
        const database = await openDatabase();
        if(ticket!==null)assertOperationTicket(subject,ticket);
        const transaction = database.transaction(["entries", "outbox", "keys"], "readwrite");
        if(ticket!==null)trackWriteTransaction(subject,transaction);
        const stored = { ...entry, subject, storageId: storageId(subject, entry.id) };
        try{
            const persisted = await requestResult(transaction.objectStore("keys").get(masterKeyId(subject)));
            const master = unlockedMasters.get(subject);
            if (master?.wrappedMasterKey && persisted?.wrappedMasterKey !== master.wrappedMasterKey) {
                transaction.abort(); throw coded("VAULT_LOCKED", "Your vault changed in another tab. Unlock it again before making changes.");
            }
            const sequence = await advanceLocalState(transaction, subject, true);
            if (operation === "PUT") transaction.objectStore("entries").put(stored);
            else transaction.objectStore("entries").delete(stored.storageId);
            transaction.objectStore("outbox").put({
                mutationId: entry.mutationId || crypto.randomUUID(), subject, entryId: entry.id,
                operation, payload: operation === "PUT" ? wireEntry(stored) : null, createdAt: Date.now(), sequence, attempts: 0
            });
            await transactionDone(transaction);if(ticket!==null)assertOperationTicket(subject,ticket);
        }finally{if(ticket!==null)untrackWriteTransaction(subject,transaction);releaseDatabase(database);}
        return stored;
    }

    async function addOtpUri(subject, uri) {
        const master=acceptedMutation(subject);
        const parsed = parseOtpAuthUri(uri);
        const id = crypto.randomUUID();
        const mutationId = crypto.randomUUID();
        const keyRecord = { id:keyId(subject,master.currentVersion), subject, version:master.currentVersion,
            key:await deriveVersionKey(master,subject,master.currentVersion), createdAt:Date.now() };
        const encrypted = await encryptSecret(subject, id, parsed.secret, keyRecord);
        const entry = {
            id, ...(await sealLabels(subject, id, parsed, keyRecord)), ...encrypted,
            algorithm: parsed.algorithm, digits: parsed.digits, periodSeconds: parsed.periodSeconds,
            createdAtEpochMillis: Date.now(), updatedAtEpochMillis: Date.now(), mutationId, baseMutationId: null
        };
        await writeEntryAndOutbox(subject, entry,"PUT",null);
        const generated=await totp(parsed.secret,entry.algorithm,entry.digits,entry.periodSeconds);
        return { ...wireEntry(entry), issuer: parsed.issuer, accountName: parsed.accountName, ...generated, period:entry.periodSeconds, serverEpochMillis:Date.now(), validForMillis:generated.validUntilEpochMillis-Date.now() };
    }

    async function updateEntry(subject, id, issuer, accountName) {
        acceptedMutation(subject);
        validateUuidV4(id, "Entry ID");
        const entry = await get("entries", storageId(subject, id));
        if (!entry) throw new Error("This account no longer exists. It may have been removed on another device.");
        const mutationId = crypto.randomUUID();
        const labels = { issuer: issuer.trim(), accountName: accountName.trim() };
        validateLabels(labels.issuer, labels.accountName);
        const sealed = await sealLabels(subject, id, labels, await keyFor(subject, entry.keyVersion), Boolean(entry.encryptedLabel));
        // baseMutationId: the version this edit was made from. The server refuses the edit (CONFLICT) when the
        // account changed elsewhere in the meantime, or (DELETED) when it was removed, instead of overwriting.
        const updated = { ...entry, ...sealed, mutationId, baseMutationId: entry.mutationId || null, updatedAtEpochMillis: Date.now() };
        await writeEntryAndOutbox(subject, updated,"PUT",null);
        return { ...wireEntry(updated), ...labels };
    }

    async function deleteEntry(subject, id) {
        acceptedMutation(subject);
        validateUuidV4(id, "Entry ID");
        await writeEntryAndOutbox(subject, { id, mutationId: crypto.randomUUID() }, "DELETE",null);
        // An account kept on this device only is no longer kept once removed.
        const database = await openDatabase();
        const transaction = database.transaction("keys", "readwrite");
        transaction.objectStore("keys").delete(parkedId(subject, id));
        await transactionDone(transaction);
    }

    // Called only after the API acknowledges a user-confirmed deletion. Failed network requests keep
    // the local entry intact; an acknowledgement removes any older uploads of that same UUID as well.
    async function acceptServerDeletion(subject, id) {
        validateUuidV4(id, "Entry ID");
        const database = await openDatabase();
        const transaction = database.transaction(["entries", "outbox", "keys"], "readwrite");
        transaction.objectStore("entries").delete(storageId(subject, id));
        transaction.objectStore("keys").delete(parkedId(subject, id));
        const queue = transaction.objectStore("outbox");
        const records = await requestResult(queue.index("bySubject").getAll(IDBKeyRange.only(subject)));
        for (const item of records) if (item.entryId === id) queue.delete(item.mutationId);
        await advanceLocalState(transaction, subject);
        await transactionDone(transaction);
        markSynced(subject);
    }

    async function replaceFromServer(subject, remoteEntries, ticket = null, deletedIds = null, generation = null) {
        if(ticket!==null)assertOperationTicket(subject,ticket);
        // Validate before queuing deletes: throwing from an async continuation does not abort IndexedDB.
        for (const entry of remoteEntries) validateUuidV4(entry?.id, "Server entry ID");
        for (const id of deletedIds || []) validateUuidV4(id, "Deleted server entry ID");
        // Separate server queries may include an entry and its tombstone in one delta. Deletion wins.
        const deleted = deletedIds ? new Set(deletedIds) : null;
        if (deleted) remoteEntries = remoteEntries.filter(entry => !deleted.has(entry.id));
        const database = await openDatabase();
        const transaction = database.transaction(["keys", "entries", "outbox"], "readwrite");
        if(ticket!==null)trackWriteTransaction(subject,transaction);
        try{
            const keys = transaction.objectStore("keys");
            const local = await requestResult(keys.get(localStateId(subject)));
            if (generation !== null && (local?.generation || 0) !== generation) {
                await transactionDone(transaction); return false;
            }
            const pending = await requestResult(transaction.objectStore("outbox").index("bySubject").getAll(subject));
            const pendingIds = new Set(pending.map(item => item.entryId));
            const remoteIds = new Set(remoteEntries.map(entry => entry.id));
            const keyRecords = await requestResult(keys.index("bySubject").getAll(subject));
            for (const record of keyRecords.filter(record => record.parkedChange)) {
                if (remoteIds.has(record.entryId)) keys.delete(record.id);
                else pendingIds.add(record.entryId);
            }
            const store = transaction.objectStore("entries");
            const existing = await requestResult(store.index("bySubject").getAll(IDBKeyRange.only(subject)));
            // Full list: anything the server no longer has is removed. Changes only: just the reported deletions.
            for (const entry of existing) {
                const gone = deleted ? deleted.has(entry.id) : !remoteIds.has(entry.id);
                if (gone && !pendingIds.has(entry.id)) store.delete(entry.storageId);
            }
            for (const entry of remoteEntries) {
                if (!pendingIds.has(entry.id)) store.put({ ...entry, subject, storageId: storageId(subject, entry.id) });
            }
            await advanceLocalState(transaction, subject);
            await transactionDone(transaction);if(ticket!==null)assertOperationTicket(subject,ticket);
            return true;
        }
        catch(error){try{transaction.abort();}catch{/* already finished */}throw error;}
        finally{if(ticket!==null)untrackWriteTransaction(subject,transaction);releaseDatabase(database);}
    }

    async function removeOutbox(mutationIds, subject = null, ticket = null) {
        const ids = Array.isArray(mutationIds) ? mutationIds : [mutationIds];
        if (!ids.length) return;
        if(ticket!==null)assertOperationTicket(subject,ticket);
        const database = await openDatabase();
        // Several acknowledged changes are removed in one transaction.
        const transaction = database.transaction("outbox", "readwrite");
        if(ticket!==null)trackWriteTransaction(subject,transaction);
        for (const id of ids) transaction.objectStore("outbox").delete(id);
        try{await transactionDone(transaction);if(ticket!==null)assertOperationTicket(subject,ticket);}
        finally{if(ticket!==null)untrackWriteTransaction(subject,transaction);releaseDatabase(database);}
    }

    // Bumped whenever this client changes server state, so a vault list fetched earlier
    // (for example by the startup bootstrap request) is only reused while still current.
    function syncGeneration(subject) { return syncGenerations.get(subject) || 0; }
    function markSynced(subject) { syncGenerations.set(subject, syncGeneration(subject) + 1); }

    // Changes the server refuses for good are dropped from the queue so they cannot block every later change:
    // an account added with a key that was rotated away (STALE_KEY), a vault that was reset (VAULT_RESET), an
    // edit of an account that changed (CONFLICT) or was deleted (DELETED) on another device, and any other
    // change the server rejects as invalid (400/413, reported as REJECTED). The caller tells the user; the next
    // sync then downloads the full list so this device shows the server's version again.
    const DROPPED_CHANGE_CODES = new Set(["STALE_KEY", "VAULT_RESET", "CONFLICT", "DELETED"]);
    function isPermanentRejection(error) {
        return DROPPED_CHANGE_CODES.has(error?.code) || error?.status === 400 || error?.status === 413;
    }
    function batchError(details) {
        const error = new Error(details?.message || "Lockstep could not sync. It will try again.");
        error.code = details?.code || "REQUEST_FAILED";
        if (details?.status) error.status = details.status;
        return error;
    }
    // A new account the server refuses for a reason other than a conflict (for example the account limit, or a
    // change it considers invalid) is not thrown away: it leaves the queue but stays on this device ("kept
    // locally"), so its secret is never lost. Edits and deletions refused this way are dropped.
    function keepsLocally(error, item) {
        return item?.operation === "PUT" && !item.payload?.baseMutationId && !["CONFLICT", "DELETED", "VAULT_RESET"].includes(error?.code);
    }
    function parkedId(subject, entryId) { return `${subject}:parked:${entryId}`; }
    async function setAside(subject, item, error) {
        const database = await openDatabase();
        const transaction = database.transaction(["outbox", "keys"], "readwrite");
        const queue = transaction.objectStore("outbox");
        // Only if that upload is still queued: a re-encrypted copy queued meanwhile (rescueStrandedEntries) replaced
        // it, and must not be marked "kept locally" by this late refusal.
        const still = await requestResult(queue.get(item.mutationId));
        if (still) {
            queue.delete(item.mutationId);
            transaction.objectStore("keys").put({ id: parkedId(subject, item.entryId), subject, parkedChange: true, entryId: item.entryId,
                code: error?.code || null, message: error?.message || "", at: Date.now() });
        }
        await transactionDone(transaction);
    }
    async function parkedEntryIds(subject) {
        return new Set((await subjectRecords("keys", subject)).filter(record => record.subject === subject && record.parkedChange).map(record => record.entryId));
    }
    async function refuseChange(subject, item, error) {
        if (keepsLocally(error, item)) {
            const staleKey = error?.code === "STALE_KEY";
            await setAside(subject, item, error);
            error.code = "KEPT_LOCALLY";
            error.dropped = true;
            error.message = staleKey
                ? "An account added while offline was encrypted with your previous recovery key. It is kept on this device and is re-encrypted with the new key the next time you unlock."
                : `Lockstep could not save an account to the server (${error.message}). It is kept on this device only; you can upload it again or export it.`;
            return error;
        }
        await removeOutbox(item.mutationId);
        return droppedError(error);
    }
    function droppedError(error) {
        if (!DROPPED_CHANGE_CODES.has(error.code)) error.code = "REJECTED";
        error.dropped = true;
        if (error.code === "CONFLICT") error.message = "An account was changed on another device at the same time. The newer version was kept.";
        else if (error.code === "DELETED") error.message = "An account you edited was removed on another device, so the edit was discarded.";
        else if (error.code === "REJECTED") error.message = `Lockstep refused a change, so it was not saved: ${error.message}`;
        return error;
    }

    async function flushOutboxNow(subject, transport) {
        const records = await subjectRecords("outbox", subject);
        records.sort((a, b) => (a.sequence || 0) - (b.sequence || 0) || a.createdAt - b.createdAt || a.mutationId.localeCompare(b.mutationId));
        // Legacy queues have only wall-clock timestamps. Honour dependencies even if the clock moved backwards.
        const byMutation = new Map(records.map(item => [item.mutationId, item]));
        const queue = [], visited = new Set();
        for (const item of records) {
            const path = [], visiting = new Set();
            let next = item;
            while (next && !visited.has(next.mutationId)) {
                if (visiting.has(next.mutationId)) throw new Error("The upload queue has an invalid mutation dependency.");
                visiting.add(next.mutationId); path.push(next); next = byMutation.get(next.payload?.baseMutationId);
            }
            while (path.length) { const queued = path.pop(); visited.add(queued.mutationId); queue.push(queued); }
        }
        let synced = 0, index = 0;
        while (index < queue.length) {
            // Several queued changes go to the server in one request when it supports batching.
            // Operations are applied in order and stop at the first failure, exactly like the loop below.
            if (typeof transport.batch === "function" && queue.length - index > 1) {
                const chunk = queue.slice(index, index + FLUSH_BATCH_SIZE);
                const result = await transport.batch(chunk.map(item => ({
                    operation: item.operation, entryId: item.entryId, mutationId: item.mutationId,
                    ...(item.operation === "PUT" ? { payload: item.payload } : {})
                })));
                if (result) {
                    const applied = Math.max(0, Math.min(chunk.length, Number(result.applied) || 0));
                    await removeOutbox(chunk.slice(0, applied).map(item => item.mutationId));
                    if (applied) { synced += applied; markSynced(subject); }
                    index += applied;
                    const error = result.error ? batchError(result.error) : null;
                    if (error && isPermanentRejection(error) && index < queue.length) {
                        const refused = queue[index];
                        index++;
                        syncCursors.delete(subject); // the next sync takes the full list, so the dropped change disappears here too
                        throw await refuseChange(subject, refused, error);
                    }
                    if (error) throw error;
                    if (applied < chunk.length) throw batchError({ message: "Sync did not finish. Lockstep will try again." });
                    continue;
                }
                // null: this server has no batch endpoint, so fall back to one request per change.
            }
            const item = queue[index];
            try {
                if (item.operation === "PUT") await transport.put(item.entryId, item.payload);
                else await transport.delete(item.entryId, item.mutationId);
            } catch (error) {
                if (isPermanentRejection(error)) { syncCursors.delete(subject); throw await refuseChange(subject, item, error); } // refused for good
                throw error;
            }
            await removeOutbox(item.mutationId);
            synced++; markSynced(subject); index++;
        }
        return { synced, pending: (await subjectRecords("outbox", subject)).filter(item => item.subject === subject).length };
    }

    // One upload at a time per account, also across browser tabs (Web Locks): two tabs sending the same queue
    // could otherwise deliver an older change after a newer one.
    function exclusiveFlush(subject, transport) {
        if (globalThis.navigator?.locks?.request) return navigator.locks.request(`lockstep-outbox:${subject}`, () => flushOutboxNow(subject, transport));
        return flushOutboxNow(subject, transport);
    }
    async function flushOutbox(subject, transport) {
        const previous=outboxFlushes.get(subject)||Promise.resolve();
        const current=previous.catch(()=>null).then(()=>exclusiveFlush(subject,transport));
        outboxFlushes.set(subject,current);
        try{return await current;}finally{if(outboxFlushes.get(subject)===current)outboxFlushes.delete(subject);}
    }

    // Delta sync: after a full list the server returns a cursor, and later syncs ask only for entries
    // changed or deleted since then. A full list still runs at least every FULL_SYNC_MILLIS.
    const FULL_SYNC_MILLIS = 30 * 60 * 1000;
    // The cursor is also saved on this device (next to the vault it describes), so reopening the app asks
    // only for what changed. A saved cursor is used at startup for up to STARTUP_DELTA_MILLIS after the last
    // full list; the server also answers with the full list for cursors older than its deletion records.
    const STARTUP_DELTA_MILLIS = 12 * 60 * 60 * 1000;
    const syncCursors = new Map();
    function cursorRecordId(subject) { return `${subject}:sync-cursor`; }
    // A different vault key came from the server (rotation, passphrase change, or a vault deleted and created
    // again). The next sync takes the full list: a vault created anew has no deletion records for the accounts
    // of the one it replaced, so only a full list removes them from this device. Also forgets the saved cursor,
    // so a restart cannot use it either.
    async function forgetSyncCursor(subject) {
        syncCursors.delete(subject);
        await put("keys", { id: cursorRecordId(subject), subject, syncCursor: true, cursor: null, fullAt: 0 }).catch(() => null);
    }
    function rememberCursor(subject, pulled) {
        if (pulled.cursor == null) { syncCursors.delete(subject); return; }
        const previous = syncCursors.get(subject);
        const saved = { cursor: pulled.cursor, fullAt: pulled.full ? Date.now() : previous?.fullAt || 0 };
        syncCursors.set(subject, saved);
        if (saved.fullAt) put("keys", { id: cursorRecordId(subject), subject, syncCursor: true, ...saved }).catch(() => null);
    }
    // The cursor to send with the startup request, or null for a full list.
    async function startupCursor(subject) {
        try {
            const pending = (await subjectRecords("outbox", subject)).some(item => item.subject === subject);
            const saved = syncCursors.get(subject) || await get("keys", cursorRecordId(subject));
            if (!saved || !Number.isFinite(saved.cursor) || !saved.fullAt || Date.now() - saved.fullAt > STARTUP_DELTA_MILLIS) return null;
            if (!(await localEncryptedEntries(subject)).length && !pending) return null; // nothing local to update
            if (!syncCursors.has(subject)) syncCursors.set(subject, { cursor: saved.cursor, fullAt: saved.fullAt });
            return saved.cursor;
        } catch { return null; }
    }
    async function pullRemote(subject, transport, prefetched, generation) {
        // Reuse a list fetched moments ago (startup bootstrap) unless this client has changed the server since.
        // A startup response for a saved cursor holds only the changes since then.
        if (prefetched && Array.isArray(prefetched.entries) && prefetched.generation === syncGeneration(subject) && prefetched.localGeneration === generation) {
            const full = prefetched.full !== false;
            return { entries: prefetched.entries, deletedIds: full ? null : (prefetched.deletedIds || []), cursor: prefetched.cursor ?? null, full };
        }
        if (typeof transport.changes === "function") {
            const known = syncCursors.get(subject);
            const delta = known && Date.now() - known.fullAt < FULL_SYNC_MILLIS;
            const result = await transport.changes(delta ? known.cursor : null);
            if (result && Array.isArray(result.entries)) {
                const full = !delta || Boolean(result.full);
                return { entries: result.entries, deletedIds: full ? null : (result.deletedIds || []), cursor: result.cursor ?? null, full };
            }
        }
        return { entries: await transport.list(), deletedIds: null, cursor: null, full: true };
    }

    async function synchronize(subject, transport, allowLockedPull = false, prefetched = null) {
        const previous = syncRuns.get(subject) || Promise.resolve();
        const run = () => synchronizeNow(subject, transport, allowLockedPull, prefetched);
        const current = previous.catch(() => null).then(() => navigator?.locks?.request
            ? navigator.locks.request(`lockstep-sync:${subject}`, run) : run());
        syncRuns.set(subject, current);
        try { return await current; } finally { if (syncRuns.get(subject) === current) syncRuns.delete(subject); }
    }
    async function synchronizeNow(subject, transport, allowLockedPull, prefetched) {
        // While the recovery key rotates, the rotation itself brings this device up to date.
        if (rotatingSubjects.has(subject)) return { synced: 0, pending: await pendingCount(subject) };
        // A change the server refused for good is dropped (see flushOutboxNow); the rest of the queue is still
        // sent and the list is still downloaded, and the reason comes back as `notice` for the user.
        let flushed = null, dropped = null;
        for (let attempt = 0; attempt < 5 && !flushed; attempt++) {
            try { flushed = await flushOutbox(subject, transport); }
            catch (error) { if (!error?.dropped) throw error; dropped = error; }
        }
        if (!flushed) flushed = { synced: 0, pending: await pendingCount(subject) };
        if (dropped) flushed.notice = dropped.message;
        if(!unlockedMasters.has(subject)&&!allowLockedPull)return flushed;
        try {
            const ticket=unlockedMasters.has(subject)?operationTicket(subject):null;
            const generation = await localGeneration(subject);
            const pulled = await pullRemote(subject, transport, prefetched, generation);
            const remote = pulled.entries;
            if(ticket!==null)assertOperationTicket(subject,ticket);
            const applied = await vaultWrite(subject, () => replaceFromServer(subject, remote,ticket,pulled.deletedIds,generation), true);
            if(ticket!==null)assertOperationTicket(subject,ticket);
            if (applied) rememberCursor(subject, pulled);
        } catch (error) {
            // The refused change is already out of the queue: the user must still hear about it.
            if (dropped && error && typeof error === "object") error.notice = dropped.message;
            throw error;
        }
        return { synced:flushed.synced, pending: (await subjectRecords("outbox", subject)).filter(item => item.subject === subject).length, ...(dropped ? { notice: dropped.message } : {}) };
    }

    async function pendingCount(subject) {
        const database = await openDatabase();
        const transaction = database.transaction("outbox", "readonly");
        const count = await requestResult(transaction.objectStore("outbox").index("bySubject").count(subject));
        await transactionDone(transaction);
        return count;
    }

    async function otpAuthUri(subject, id) {
        const ticket = operationTicket(subject);
        const entry = await get("entries", storageId(subject, id));
        if (!entry) throw new Error("This account no longer exists. It may have been removed on another device.");
        const secret = await decryptSecret(subject, entry);
        const labels = await entryLabels(subject, entry);
        const label = encodeURIComponent(labels.issuer + ":" + labels.accountName);
        const parameters = new URLSearchParams({
            secret, issuer: labels.issuer, algorithm: entry.algorithm, digits: String(entry.digits), period: String(entry.periodSeconds)
        });
        assertOperationTicket(subject, ticket);
        return `otpauth://totp/${label}?${parameters}`;
    }

    async function exportText(subject) {
        const ticket = operationTicket(subject);
        const uris = [];
        let skipped = 0;
        for (const entry of await localEncryptedEntries(subject)) {
            try { uris.push(await otpAuthUri(subject, entry.id)); }
            catch (error) { if (error?.code === "VAULT_LOCKED") throw error; skipped++; }
        }
        if (!uris.length && skipped) throw new Error("None of your accounts could be opened on this device, so there is nothing to export.");
        const note = skipped ? `# ${skipped} account${skipped === 1 ? "" : "s"} could not be opened on this device and ${skipped === 1 ? "is" : "are"} not included.\n` : "";
        assertOperationTicket(subject, ticket);
        return "# Lockstep TOTP backup\n# Keep this file private. Each URI contains an authenticator secret.\n" + note + uris.join("\n") + (uris.length ? "\n" : "");
    }

    async function exportRecoveryKey(subject) {
        const ticket = operationTicket(subject);
        const master = await masterKey(subject, false);
        assertOperationTicket(subject, ticket);
        if (!master) throw new Error("This vault does not have a local recovery key yet.");
        const raw = base64ToBytes(master.raw);
        return `LS2-M-${base64Url(raw)}`;
    }

    async function importRecoveryKey(subject, recoveryKey, passphrase) {
        const ticket = operationTicket(subject, false);
        const generation = await localGeneration(subject);
        requireNewPassphrase(passphrase);
        const match = /^LS2-M-([A-Za-z0-9_-]{43})$/.exec(recoveryKey.trim());
        if (!match) throw new Error("This is not a valid Lockstep recovery key.");
        const raw = fromBase64Url(match[1]);
        if (raw.length !== 32) throw new Error("This recovery key is incomplete. Check that you copied all of it.");
        const candidateEntries = await localEncryptedEntries(subject);
        if (candidateEntries.length === 0) {
            throw new Error("No encrypted accounts are available to verify this recovery key. Reset the vault to start again.");
        }
        const currentVersion = Math.max(1, ...candidateEntries.map(entry => entry.keyVersion));
        const candidateMaster = { raw: bytesToBase64(raw), key: await importMaster(raw) };
        // Any account encrypted with the current key proves the recovery key (a single damaged account must not
        // make a correct key look wrong). A wrong key opens none of them.
        const key = await deriveVersionKey(candidateMaster, subject, currentVersion);
        let matches = false;
        let attempted=0;
        for (const candidate of candidateEntries.filter(entry => entry.keyVersion === currentVersion)) {
            assertOperationTicket(subject,ticket,false);
            if(attempted++ && attempted%20===0){await new Promise(resolve=>setTimeout(resolve,0));assertOperationTicket(subject,ticket,false);}
            try {
                await crypto.subtle.decrypt(
                    { name: "AES-GCM", iv: base64ToBytes(candidate.secretIv), additionalData: associatedData(subject, candidate.id, candidate.keyVersion), tagLength: 128 },
                    key, base64ToBytes(candidate.encryptedSecret));
                matches = true; break;
            } catch { /* try the next account */ }
        }
        assertOperationTicket(subject,ticket,false);
        if (!matches) throw new Error("This recovery key does not match the encrypted vault.");
        const record = await wrappedMasterRecord(subject, raw, currentVersion, passphrase);
        assertOperationTicket(subject, ticket, false);
        const database = await openDatabase();
        assertOperationTicket(subject, ticket, false);
        const transaction = database.transaction(["keys", "entries", "outbox"], "readwrite");
        trackWriteTransaction(subject, transaction);
        try {
            const keys = transaction.objectStore("keys");
            const state = await requestResult(keys.get(localStateId(subject)));
            if ((state?.generation || 0) !== generation) throw coded("VAULT_LOCKED", "Your vault changed while restoring. Try again.");
            const previousRecord = await requestResult(keys.get(masterKeyId(subject)));
            if (previousRecord?.wrappedMasterKey && previousRecord.currentVersion < currentVersion) {
                const queued = await requestResult(transaction.objectStore("outbox").index("bySubject").getAll(subject));
                const parked = (await requestResult(keys.index("bySubject").getAll(subject))).filter(item => item.parkedChange);
                const strandedIds = new Set([...queued.filter(item => item.operation === "PUT" && !item.payload?.baseMutationId).map(item => item.entryId), ...parked.map(item => item.entryId)]);
                const entries = await requestResult(transaction.objectStore("entries").index("bySubject").getAll(subject));
                if (entries.some(entry => strandedIds.has(entry.id) && entry.keyVersion === previousRecord.currentVersion)) {
                    const { pendingUpload, serverRevision, ...wrapped } = previousRecord;
                    keys.put({ ...wrapped, id: retiredId(subject, previousRecord.currentVersion), retiredMaster: true });
                }
            }
            assertOperationTicket(subject, ticket, false);
            markPendingUpload(record, previousRecord, subject);
            keys.put(record);
            await advanceLocalState(transaction, subject);
            await transactionDone(transaction);
            assertOperationTicket(subject, ticket, false);
        } catch (error) {
            try { transaction.abort(); } catch { /* already finished */ }
            assertOperationTicket(subject, ticket, false);
            throw error;
        } finally { untrackWriteTransaction(subject, transaction); releaseDatabase(database); }
        unlockedMasters.set(subject, { ...candidateMaster, currentVersion, createdAt: record.createdAt, wrappedMasterKey: record.wrappedMasterKey });
        return currentVersion;
    }


    // True key rotation: brand-new 256-bit master key, every account re-encrypted under it, new passphrase wrap.
    // The new wrapped key, re-encrypted entries and their outbox mutations are committed in ONE IndexedDB
    // transaction, so a failure can never leave entries encrypted under a key that was not saved.
    // Recovery-key rotation in two steps. prepareMasterRotation re-encrypts everything in memory only;
    // the caller sends the result to POST /api/v1/vault/rotate, which swaps the server copy atomically,
    // and only then commitMasterRotation stores it on this device. A failure at any point leaves every
    // copy consistent (old everywhere, or new on the server and adopted by this device on its next sync).
    async function prepareMasterRotation(subject, passphrase) {
        assertNotRotating(subject);
        const ticket=operationTicket(subject);
        requirePassphrase(passphrase);
        // From here until commitMasterRotation or cancelMasterRotation, no local change or sync can slip in
        // between the snapshot taken below and the commit (the server checks only its own copy).
        const rotation = { release: await holdRotationWrite(subject) };
        try { assertOperationTicket(subject, ticket); } catch (error) { rotation.release(); throw error; }
        rotatingSubjects.set(subject, rotation);
        rotation.timer = setTimeout(() => endRotation(subject, rotation), 5 * 60 * 1000);
        try {
            return await prepareRotationSnapshot(subject, passphrase, ticket, rotation);
        } catch (error) { endRotation(subject, rotation); throw error; }
    }
    function endRotation(subject, rotation) {
        clearTimeout(rotation?.timer);
        rotation?.release?.();
        if (rotatingSubjects.get(subject) === rotation) rotatingSubjects.delete(subject);
    }
    // Called when the server refused or the request failed: nothing changed on this device.
    function cancelMasterRotation(prepared) { if (prepared) endRotation(prepared.subject, prepared.rotation); }
    async function prepareRotationSnapshot(subject, passphrase, ticket, rotation) {
        await unlock(subject, passphrase,ticket); // proves the passphrase and loads the current master
        assertOperationTicket(subject,ticket);
        await outboxFlushes.get(subject)?.catch(() => null); // a flush already running finishes first
        const parked = (await parkedEntryIds(subject)).size;
        if (parked) throw new Error(`${parked} account${parked === 1 ? " is" : "s are"} kept on this device only (the server refused ${parked === 1 ? "it" : "them"}). Export or remove ${parked === 1 ? "it" : "them"} before rotating the recovery key.`);
        const pending = (await subjectRecords("outbox", subject)).filter(item => item.subject === subject).length;
        if (pending) throw new Error(`${pending} change${pending === 1 ? " has" : "s have"} not synced yet. Try again once ${pending === 1 ? "it has" : "they have"} synced.`);
        const entries = await localEncryptedEntries(subject);
        const plaintext = [];
        for (const entry of entries) plaintext.push([entry, await decryptSecret(subject, entry), await entryLabels(subject, entry)]);
        const previous = unlockedMasters.get(subject);
        const version = previous.currentVersion + 1;
        const raw = crypto.getRandomValues(new Uint8Array(32));
        const createdAt = Date.now();
        const master = { raw: bytesToBase64(raw), key: await importMaster(raw), currentVersion: version, createdAt };
        const keyRecord = { id: keyId(subject, version), subject, version, key: await deriveVersionKey(master, subject, version), createdAt };
        const wrapped = await wrappedMasterRecord(subject, raw, version, passphrase, createdAt);
        const updated = [];
        for (const [entry, secret, labels] of plaintext) {
            const encrypted = await encryptSecret(subject, entry.id, secret, keyRecord);
            const sealed = await sealLabels(subject, entry.id, labels, keyRecord, Boolean(entry.encryptedLabel));
            updated.push(wireEntry({ ...entry, ...encrypted, ...sealed, mutationId: crypto.randomUUID(), baseMutationId: undefined, updatedAtEpochMillis: Date.now() }));
        }
        return {
            subject, master, wrapped, version, entries: updated, ticket, rotation, expectedRevision: await expectedRevision(subject),
            previous: entries.map(entry => ({ id: entry.id, mutationId: entry.mutationId })),
            recoveryKey: `LS2-M-${base64Url(raw)}`,
            wrappedKey: { currentVersion: wrapped.currentVersion, createdAt: wrapped.createdAt, wrappedAt: wrapped.wrappedAt, wrapping: wrapped.wrapping,
                iterations: wrapped.iterations, salt: wrapped.salt, iv: wrapped.iv, wrappedMasterKey: wrapped.wrappedMasterKey,
                ...(wrapped.wrapping === ARGON2ID_WRAPPING ? { memoryKiB: wrapped.memoryKiB, parallelism: wrapped.parallelism } : {}) }
        };
    }

    async function commitMasterRotation(prepared, serverEntries = null, revision = null) {
        const subject = prepared.subject;
        try {
            return await commitRotation(prepared, serverEntries, revision);
        } finally { endRotation(subject, prepared.rotation); }
    }
    async function commitRotation(prepared, serverEntries, revision) {
        const subject = prepared.subject;
        assertOperationTicket(subject,prepared.ticket);
        if (rotatingSubjects.get(subject) !== prepared.rotation) throw new Error("The recovery key rotation timed out on this device. Unlock again to load the new key.");
        const stored = Array.isArray(serverEntries) ? serverEntries : prepared.entries;
        const wrapped = { ...prepared.wrapped, serverRevision: Number.isInteger(revision) ? revision : null };
        if (Number.isInteger(revision)) knownRevisions.set(subject, revision);
        const database = await openDatabase();
        const transaction = database.transaction(["keys", "entries", "outbox"], "readwrite");
        trackWriteTransaction(subject,transaction);
        try {
            // Retain the old wrapper for drafts accepted by older clients without the cross-tab lock.
            const keys = transaction.objectStore("keys");
            const old = await requestResult(keys.get(masterKeyId(subject)));
            const queued = await requestResult(transaction.objectStore("outbox").index("bySubject").getAll(subject));
            const parked = (await requestResult(keys.index("bySubject").getAll(subject))).filter(k => k.parkedChange);
            if (old?.wrappedMasterKey && (queued.some(item => item.operation === "PUT" && item.payload?.keyVersion < prepared.version) || parked.length)) {
                keys.put({ ...old, id: retiredId(subject, old.currentVersion), retiredMaster: true });
            }
            transaction.objectStore("keys").put(wrapped);
            for (const entry of stored) transaction.objectStore("entries").put({ ...entry, subject, storageId: storageId(subject, entry.id) });
            await advanceLocalState(transaction, subject);
            await transactionDone(transaction);
        } finally { untrackWriteTransaction(subject,transaction);releaseDatabase(database); }
        prepared.master.wrappedMasterKey = wrapped.wrappedMasterKey;
        unlockedMasters.set(subject, prepared.master);
        markSynced(subject);
        return { version: prepared.version, count: stored.length, recoveryKey: prepared.recoveryKey };
    }

    // Older entries still carry readable names; re-save them encrypted (a few at a time) once unlocked.
    async function sealPlaintextLabels(subject, limit = 100) {
        if (!unlockedMasters.has(subject) || !labelEncryption) return 0;
        const pendingIds = new Set((await subjectRecords("outbox", subject)).filter(item => item.subject === subject).map(item => item.entryId));
        let sealed = 0;
        for (const entry of await localEncryptedEntries(subject)) {
            if (sealed >= limit) break;
            if (entry.encryptedLabel || pendingIds.has(entry.id)) continue;
            // An older entry whose names no longer pass the checks (for example an empty name) is skipped, so it
            // cannot stop the others from being sealed.
            try { await updateEntry(subject, entry.id, entry.issuer, entry.accountName); sealed++; }
            catch (error) { if (error?.code === "VAULT_LOCKED" || error?.code === "ROTATION_IN_PROGRESS") throw error; }
        }
        return sealed;
    }

    async function clearSubject(subject) {
        syncCursors.delete(subject);
        knownRevisions.delete(subject);
        const database = await openDatabase();
        const transaction = database.transaction(["keys", "entries", "outbox"], "readwrite");
        const previous = await requestResult(transaction.objectStore("keys").get(localStateId(subject)));
        for (const storeName of ["keys", "entries", "outbox"]) {
            const store = transaction.objectStore(storeName);
            for (const record of await requestResult(store.index("bySubject").getAll(IDBKeyRange.only(subject)))) {
                if (record.subject !== subject) continue;
                const key = storeName === "keys" ? record.id : storeName === "entries" ? record.storageId : record.mutationId;
                store.delete(key);
            }
        }
        transaction.objectStore("keys").put({ id: localStateId(subject), subject, localState: true,
            generation: (previous?.generation || 0) + 1, erasureGeneration:(previous?.erasureGeneration || 0)+1, sequence: previous?.sequence || 0 });
        await transactionDone(transaction);
        releaseDatabase(database);
        unlockedMasters.delete(subject);
    }

    globalThis.LockstepVault = {
        acceptServerDeletion, addOtpUri, cancelMasterRotation, checkPassphrase, clearSubject, configurePassphrase, decryptBackup, encryptBackup, isEncryptedBackup, deleteEntry, expectedRevision, exportRecoveryKey, exportSessionKey, exportText, exportWrappedKey, flushOutbox, forgetSessionKey, importRecoveryKey, isUnlocked, keyState, listEntries, lock,
        localGeneration, localEncryptedEntries, refreshRotationKey, serverVaultReplaced, adoptReplacedServerVault, markWrappedKeySynced, setArgon2idWrapping, upgradeWrapping, needsWrappingUpgrade, rescueStrandedEntries, retryLocalOnly, otpAuthUri, parseOtpAuthUri, pendingCount, pendingWrappedKeyUpload, restoreSessionKey, passkeyOpensWrappedKey, prepareMasterRotation, setLabelEncryption, commitMasterRotation, sealPlaintextLabels, startupCursor, synchronize, synchronizeWrappedKey, syncGeneration, unlock, updateEntry
    };
    for (const name of ["addOtpUri", "updateEntry", "retryLocalOnly", "configurePassphrase", "deleteEntry", "sealPlaintextLabels",
        "synchronizeWrappedKey", "rescueStrandedEntries", "importRecoveryKey", "refreshRotationKey", "upgradeWrapping", "adoptReplacedServerVault"]) {
        const action = globalThis.LockstepVault[name];
        globalThis.LockstepVault[name] = (subject, ...args) => {
            const ticket = lockGeneration(subject);
            return vaultWrite(subject, async () => {
                assertOperationTicket(subject, ticket, false);
                const master=unlockedMasters.get(subject);
                if(master?.wrappedMasterKey) {
                    const persisted=await get("keys",masterKeyId(subject));
                    // Verified rotation repair needs both wrappers and must preserve pending-key memory.
                    // An erased/missing wrapper never qualifies for this exception.
                    if(persisted?.wrappedMasterKey!==master.wrappedMasterKey && !(name==="refreshRotationKey" && persisted?.wrappedMasterKey)){lock(subject);throw coded("VAULT_LOCKED","This vault was removed or changed in another tab. Sign in again.");}
                }
                return action(subject, ...args);
            });
        };
    }
    globalThis.LockstepVault.acceptServerDeletion = (subject, id) => vaultWrite(subject, () => acceptServerDeletion(subject, id), true);
    globalThis.LockstepVault.markWrappedKeySynced = (subject, revision, acknowledged) => vaultWrite(subject, () => markWrappedKeySynced(subject, revision, acknowledged), true);
    globalThis.LockstepVault.clearSubject = subject => { lock(subject); return vaultWrite(subject, () => clearSubject(subject), true); };
    // Activity events can overlap. Share the initial wrap-key creation and reject stale exports.
    globalThis.LockstepVault.exportSessionKey=(subject,tabKey)=>{
        const master=unlockedMasters.get(subject);
        if(!master || typeof tabKey!=="string" || !tabKey)return Promise.resolve(null);
        const ticket=operationTicket(subject),id=sessionWrapId(subject,tabKey),existing=sessionExportRuns.get(id);
        if(existing?.master===master && existing.ticket===ticket)return existing.promise;
        const record={master,ticket};
        record.promise=vaultWrite(subject,()=>{assertOperationTicket(subject,ticket);return exportSessionKey(subject,tabKey,ticket);},true)
            .finally(()=>{if(sessionExportRuns.get(id)===record)sessionExportRuns.delete(id);});
        sessionExportRuns.set(id,record);return record.promise;
    };
    globalThis.LockstepVault.currentCode = currentCode;
})();

