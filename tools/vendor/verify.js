#!/usr/bin/env node
// Checks the vendored third-party files against tools/vendor/manifest.json: each file's SHA-256, that the
// web app and extension ship identical copies, and that every license file is present.
//   node tools/vendor/verify.js             (offline checks)
//   node tools/vendor/verify.js --upstream  (also downloads files with a "download" URL and compares them)
const fs = require("fs"), path = require("path"), crypto = require("crypto");
const root = path.resolve(__dirname, "..", "..");
const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, "manifest.json"), "utf8"));
const sha256 = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const failures = [];

(async () => {
    for (const [file, entry] of Object.entries(manifest.files)) {
        const copies = ["webapp/vendor", "extension/vendor"].map((dir) => path.join(root, dir, file));
        for (const copy of copies) {
            const actual = sha256(fs.readFileSync(copy));
            if (actual !== entry.sha256) failures.push(`${path.relative(root, copy)}: SHA-256 ${actual}, expected ${entry.sha256} (${entry.name} ${entry.version || ""})`);
            const license = path.join(path.dirname(copy), entry.licenseFile);
            if (!fs.existsSync(license)) failures.push(`${path.relative(root, license)} is missing`);
        }
        if (process.argv.includes("--upstream") && entry.download) {
            const response = await fetch(entry.download);
            if (!response.ok) { failures.push(`${file}: download failed (${response.status})`); continue; }
            const upstream = sha256(Buffer.from(await response.arrayBuffer()));
            if (upstream !== entry.sha256) failures.push(`${file}: upstream ${entry.download} has SHA-256 ${upstream}, expected ${entry.sha256}`);
            else console.log(`${file}: matches ${entry.download}`);
        }
        console.log(`${file}: ${entry.name} ${entry.version || ""} ok`);
    }
    if (failures.length) { console.error(`Vendored files do not match tools/vendor/manifest.json:\n- ${failures.join("\n- ")}`); process.exit(1); }
})().catch((error) => { console.error(error.message); process.exit(1); });
