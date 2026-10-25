# Builds webapp/vendor/argon2id.js from openpgpjs/argon2id (lib/*.js) and the clang-built wasm core.
import base64, sys, re
src, wasm, out, commit = sys.argv[1:5]
blake = open(f"{src}/lib/blake2b.js").read()
argon = open(f"{src}/lib/argon2id.js").read()
blake = blake.replace("export default function createHash(", "function createHash(")
argon = argon.replace('import blake2b from "./blake2b.js"', "const blake2b = createHash;")
argon = argon.replace("export default function argon2id(", "function argon2id(")
# The wasm core keeps its stack in the first 64 KiB of memory (linked with --stack-first); start JS buffers after it.
assert argon.count("  let offset = 0;") == 1
argon = argon.replace("  let offset = 0;", "  let offset = STACK_RESERVED;")
assert argon.count("const requiredMemory = m_ * ARGON2_BLOCK_SIZE + 10 * KB;") == 1
argon = argon.replace("const requiredMemory = m_ * ARGON2_BLOCK_SIZE + 10 * KB;", "const requiredMemory = STACK_RESERVED + m_ * ARGON2_BLOCK_SIZE + 10 * KB;")
# Also wipe the block memory (it holds data derived from the password), not only the small buffers.
assert argon.count("  allocatedMemory.fill(0) // clear sensitive contents") == 1
argon = argon.replace("  allocatedMemory.fill(0) // clear sensitive contents", "  allocatedMemory.fill(0) // clear sensitive contents\n  blockMemory.fill(0)")
wasm_b64 = base64.b64encode(open(wasm, "rb").read()).decode()
license_text = open(f"{src}/LICENSE").read().strip()
header = f"""/*
 * Argon2id (RFC 9106) for Lockstep, bundled as a classic script.
 * Source: https://github.com/openpgpjs/argon2id (commit {commit}), lib/blake2b.js and lib/argon2id.js,
 * with the WebAssembly core lib/wasm.c compiled by clang (non-SIMD build). Changes: ES module syntax removed;
 * buffers start after a 64 KiB stack area; the block memory is also wiped after hashing.
 * Exposes globalThis.LockstepArgon2id.hash(params) -> Promise<Uint8Array>.
 *
{chr(10).join(' * ' + line if line else ' *' for line in license_text.splitlines())}
 */
"""
body = f"""(() => {{
const STACK_RESERVED = 64 * 1024;
// Each source file keeps its own scope, as it had as an ES module.
const createHash = (() => {{
{blake}
return createHash;
}})();
const argon2id = (() => {{
{argon}
return argon2id;
}})();
const WASM_BASE64 = "{wasm_b64}";
let compiled = null;
function wasmModule() {{
  compiled ||= WebAssembly.compile(Uint8Array.from(atob(WASM_BASE64), (c) => c.charCodeAt(0)));
  return compiled;
}}
// Each call gets its own memory, released when the call finishes.
async function hash(params) {{
  const module = await wasmModule();
  const pages = Math.ceil((STACK_RESERVED + params.memorySize * 1024 + 64 * 1024) / (64 * 1024));
  const memory = new WebAssembly.Memory({{ initial: pages, maximum: 65536 }});
  const instance = await WebAssembly.instantiate(module, {{ env: {{ memory }} }});
  return argon2id(params, {{ memory, instance }});
}}
globalThis.LockstepArgon2id = Object.freeze({{ hash }});
}})();
"""
open(out, "w").write(header + body)
print("written", out, len(header + body))
