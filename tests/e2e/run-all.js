// Runs every browser scenario against the mock API. Usage: npm ci && npx playwright install chromium && node run-all.js
// The mock API listens on API_PORT (default 18080, so a locally running Lockstep API on 8080 is not in the way).
const { spawn } = require("child_process");
const fs = require("fs");
const os = require("os");
const path = require("path");

const API_PORT = Number(process.env.API_PORT || 18080);
const API = `http://localhost:${API_PORT}`;
const repo = path.resolve(__dirname, "../..");
const work = fs.mkdtempSync(path.join(os.tmpdir(), "lockstep-e2e-"));
// WEBAPP_DIR tests a built copy of the web app (for example the minified files of the container image).
const webappSource = process.env.WEBAPP_DIR ? path.resolve(process.env.WEBAPP_DIR) : path.join(repo, "webapp");
function copyApp(name, apiBaseUrl) {
    const target = path.join(work, name);
    fs.cpSync(webappSource, target, { recursive: true });
    fs.writeFileSync(path.join(target, "config.js"), `globalThis.LOCKSTEP_CONFIG = Object.freeze({ apiBaseUrl: ${JSON.stringify(apiBaseUrl)} });\n`);
    return target;
}
const web = copyApp("web", API);
const webCookie = copyApp("web-cookie", "/lockstep"); // same-origin API proxy -> HttpOnly cookie session
const extension = path.join(work, "extension");
fs.cpSync(path.join(repo, "extension"), extension, { recursive: true });
fs.writeFileSync(path.join(extension, "config.js"),
    `globalThis.AUTHSYNC_CONFIG = { apiBaseUrl: ${JSON.stringify(API)}, webBaseUrl: "http://localhost:5173/lockstep", googleClientId: "REPLACE_test" };\n`);
// The published manifest only allows the production API; the test copy may also reach the mock API.
const manifestPath = path.join(extension, "manifest.json");
const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
manifest.host_permissions = [...manifest.host_permissions, `${API}/*`];
// The extension's security policy only lets it connect to the production API; allow the mock API too.
manifest.content_security_policy.extension_pages = manifest.content_security_policy.extension_pages.replace("connect-src ", `connect-src ${API} `);
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2));

const ONLY = process.env.ONLY ? new Set(process.env.ONLY.split(",")) : null;
const scenarios = [
    { label: "web-main", script: "web-main.test.js", app: web },
    { label: "web-main-old-server", script: "web-main.test.js", app: web, mode: "nobootstrap" },
    { label: "web-main-service-worker", script: "web-main.test.js", app: web, env: { SW: "allow" } },
    { label: "web-main-pbkdf2", script: "web-main.test.js", app: web, env: { ARGON2ID: "0" } },
    { label: "web-session", script: "web-session.test.js", app: web },
    { label: "web-session-locked", script: "web-session.test.js", app: web, env: { LOCKED: "1" } },
    { label: "web-security", script: "web-security.test.js", app: web },
    { label: "web-rotation", script: "web-rotation.test.js", app: web },
    { label: "web-rotation-cookie", script: "web-rotation.test.js", app: webCookie },
    { label: "web-offline", script: "web-offline.test.js", app: web },
    { label: "web-revision", script: "web-revision.test.js", app: web },
    { label: "web-argon2id-reauth", script: "web-argon2id.test.js", app: web },
    { label: "web-export", script: "web-export.test.js", app: web },
    { label: "web-rotation-stale", script: "web-rotation-stale.test.js", app: web },
    { label: "web-vault-replaced", script: "web-vault-replaced.test.js", app: web },
    { label: "web-integrity", script: "web-integrity.test.js", app: web },
    { label: "web-deletion", script: "web-deletion.test.js", app: web },
    { label: "web-concurrency", script: "web-concurrency.test.js", app: web },
    { label: "web-offline-rotation", script: "web-offline-rotation.test.js", app: web },
    { label: "extension-main", script: "extension-main.test.js", extension: true },
    { label: "extension-main-pbkdf2", script: "extension-main.test.js", extension: true, env: { ARGON2ID: "0" } },
    { label: "extension-main-old-server", script: "extension-main.test.js", extension: true, env: { OLDSERVER: "1" } },
    { label: "extension-offline", script: "extension-offline.test.js", extension: true },
    { label: "extension-rotation-stale", script: "extension-rotation-stale.test.js", extension: true },
    { label: "extension-vault-replaced", script: "extension-vault-replaced.test.js", extension: true },
    { label: "extension-integrity", script: "extension-integrity.test.js", extension: true },
    { label: "cross-client-live-sync", script: "cross-client-live-sync.test.js", extension: true },
    { label: "cross-client-push", script: "cross-client-live-sync.test.js", extension: true, env: { LIVE_CHANGES: "1" } },
    { label: "cross-client-push-cookie", script: "cross-client-live-sync.test.js", extension: true, app: webCookie, env: { LIVE_CHANGES: "1" } },
    { label: "cross-client-conflicts", script: "cross-client-conflicts.test.js", extension: true, env: { LIVE_CHANGES: "1" } },
    { label: "session-replacement", script: "session-replacement.test.js", extension: true, env: { LIVE_CHANGES: "1" } },
    { label: "offline-retry", script: "offline-retry.test.js", extension: true },
    { label: "cross-client-keys", script: "cross-client-keys.test.js", extension: true, env: { LIVE_CHANGES: "1" } },
    { label: "cross-client-restore", script: "cross-client-restore.test.js", extension: true, env: { LIVE_CHANGES: "1" } },
    { label: "cross-client-pending", script: "cross-client-pending.test.js", extension: true, env: { LIVE_CHANGES: "1" } },
    { label: "popup-closed", script: "popup-closed.test.js", extension: true, env: { LIVE_CHANGES: "1" } },
    { label: "stale-google-token", script: "stale-google-token.test.js", extension: true, env: { LIVE_CHANGES: "1" } },
    { label: "no-google-token", script: "stale-google-token.test.js", extension: true, env: { LIVE_CHANGES: "1", NO_GOOGLE_TOKEN: "1" } },
    { label: "account-deleted", script: "account-deleted.test.js", extension: true, env: { LIVE_CHANGES: "1" } },
    { label: "web-away", script: "web-away.test.js", extension: true, env: { LIVE_CHANGES: "1" } },
    { label: "live-tabs", script: "live-tabs.test.js", extension: true, env: { LIVE_CHANGES: "1" } },
    { label: "live-tabs-old-server", script: "live-tabs.test.js", extension: true, env: { LIVE_CHANGES: "1", LIVE_NO_EVICT: "1" } },
    { label: "live-tabs-unshared", script: "live-tabs.test.js", extension: true, env: { LIVE_CHANGES: "1", NO_SHARE: "1" } },
];

function run(command, args, env) {
    return new Promise((resolve) => {
        const child = spawn(command, args, { cwd: __dirname, env: { ...process.env, ...env } });
        child.stdout.on("data", (data) => process.stdout.write(data));
        child.stderr.on("data", (data) => process.stderr.write(data));
        child.on("error", (error) => { console.error(`could not start ${args[0]}: ${error.message}`); resolve(1); });
        child.on("exit", (code) => resolve(code));
    });
}

// Starts the mock and waits until it says both servers are listening (or fails, e.g. a port in use).
function startMock(app, port, env) {
    return new Promise((resolve, reject) => {
        const mock = spawn(process.execPath, [path.join(__dirname, "mock-server.js"), app, String(port)],
            { cwd: __dirname, env: { ...process.env, CSP: "1", API_PORT: String(API_PORT), ...env } });
        let output = "";
        const timer = setTimeout(() => { mock.kill(); reject(new Error(`mock server did not start: ${output.trim()}`)); }, 10000);
        mock.stdout.on("data", (data) => { output += data; if (/ready/.test(output)) { clearTimeout(timer); resolve(mock); } });
        mock.stderr.on("data", (data) => { output += data; });
        mock.on("error", (error) => { clearTimeout(timer); reject(error); });
        mock.on("exit", (code) => { clearTimeout(timer); reject(new Error(`mock server exited (${code}): ${output.trim()}`)); });
    });
}

(async () => {
    const failed = [];
    let completed = 0;
    let port = Number(process.env.WEB_PORT_BASE || 5300);
    if(!Number.isInteger(port)||port<1024||port>65000)throw new Error("WEB_PORT_BASE must be an integer from 1024 to 65000");
    const selected = scenarios.filter(item => !ONLY || ONLY.has(item.label));
    for (const scenario of selected) {
        port++;
        let mock;
        try { mock = await startMock(scenario.app || web, port, scenario.env); }
        catch (error) { console.error(`[${scenario.label}] FAILED ${error.message}`); failed.push(scenario.label); completed++; continue; }
        mock.removeAllListeners("exit");
        // Noticed even if the mock stops in the middle of the scenario (a crash must fail the run, and stopping
        // it afterwards must not wait for an "exit" event that already happened).
        let mockExited = false;
        mock.once("exit", () => { mockExited = true; });
        const target = scenario.extension ? extension : String(port);
        let code = await run(process.execPath, [scenario.script, scenario.label, target, scenario.mode || ""],
            { CSP: "1", API_PORT: String(API_PORT), WEB_PORT: String(port), ...scenario.env });
        // The mock refuses key changes without a vault revision (REQUIRE_VAULT_REVISION); current apps must never hit it.
        const refused = await fetch(`http://localhost:${API_PORT}/__control`).then(r => r.json()).then(s => s.outdatedRefused).catch(() => 0);
        if (refused) { console.error(`[${scenario.label}] FAILED: ${refused} key change(s) sent without the vault revision`); code = 1; }
        if (mockExited) { console.error(`[${scenario.label}] FAILED: the mock API stopped during the scenario`); code = 1; }
        else {
            const stopped = new Promise((resolve) => mock.once("exit", resolve));
            mock.kill();
            await stopped;
        }
        if (code !== 0) failed.push(scenario.label);
        completed++;
    }
    // Every selected scenario must have run to the end; anything else is a failure, never a silent pass.
    if (completed !== selected.length) failed.push(`(incomplete run: ${completed} of ${selected.length} scenarios finished)`);
    if (!selected.length) failed.push("(no scenario selected)");
    console.log(failed.length ? `\nFAILED: ${failed.join(", ")}` : `\nAll ${selected.length} scenarios passed.`);
    process.exit(failed.length ? 1 : 0);
})();
