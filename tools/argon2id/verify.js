// Checks a built argon2id.js against the RFC 9106 test vector and openpgpjs/argon2id's own vectors.
// Usage: node tools/argon2id/verify.js [path/to/argon2id.js]   (default: webapp/vendor/argon2id.js)
const path = require("path");
require(path.resolve(process.argv[2] || path.join(__dirname, "../../webapp/vendor/argon2id.js")));
const hex = (s) => Uint8Array.from(s.match(/../g).map((h) => parseInt(h, 16)));
const p = hex("01".repeat(32));
const vectors = [
  [{ password: p, salt: hex("02".repeat(16)), passes: 3, memorySize: 32, parallelism: 4, secret: hex("03".repeat(8)), ad: hex("04".repeat(12)), tagLength: 32 },
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659"], // RFC 9106 section 5.3
  [{ password: p, salt: hex("02".repeat(16)), passes: 3, memorySize: 32, parallelism: 2, secret: hex("03".repeat(8)), ad: hex("04".repeat(12)), tagLength: 32 },
    "47c71919daf18f9d1756391f1f9f4a7df3aa9608128965f1e84c0d6fcc34db87"],
  [{ password: p, salt: hex("02".repeat(32)), passes: 3, memorySize: 65536, parallelism: 4, tagLength: 32 },
    "6904f1422410f8360c6538300210a2868f5e80cd88606ec7d6e7e93b49983cea"],
];
(async () => {
  for (const [params, expected] of vectors) {
    const tag = Buffer.from(await globalThis.LockstepArgon2id.hash(params)).toString("hex");
    if (tag !== expected) { console.error(`Argon2id vector failed: ${tag} != ${expected}`); process.exit(1); }
  }
  console.log(`Argon2id: ${vectors.length} test vectors passed.`);
})();
