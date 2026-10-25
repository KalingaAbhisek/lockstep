#!/usr/bin/env bash
# Rebuilds webapp/vendor/argon2id.js and extension/vendor/argon2id.js from openpgpjs/argon2id.
# Needs git, clang with the wasm32 target (wasm-ld), python3 and node. The result must pass verify.js.
set -euo pipefail
COMMIT=6fc76bcf69fbe07b5ec532a7912772d28f1ea43a
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
WORK="$(mktemp -d)"
git clone -q https://github.com/openpgpjs/argon2id "$WORK/argon2id"
git -C "$WORK/argon2id" checkout -q "$COMMIT"
cd "$WORK/argon2id"
# Non-SIMD core; its stack lives in the first 64 KiB of memory (the bundle keeps its buffers after it).
clang --target=wasm32 -O3 -ffreestanding -nostdlib -Wl,--no-entry -Wl,--import-memory -Wl,--stack-first -Wl,-z,stack-size=65536 \
  -Wl,--strip-all -Wl,--initial-memory=131072 -Wl,--max-memory=4294967296 -Wl,--export=G -Wl,--export=G2 -Wl,--export=xor -Wl,--export=getLZ \
  -o core.wasm lib/wasm.c
python3 "$ROOT/tools/argon2id/bundle.py" . core.wasm argon2id.js "$COMMIT"
node "$ROOT/tools/argon2id/verify.js" argon2id.js
for target in webapp extension; do cp argon2id.js "$ROOT/$target/vendor/argon2id.js"; cp LICENSE "$ROOT/$target/vendor/argon2id.LICENSE"; done
echo "Updated vendor/argon2id.js (openpgpjs/argon2id $COMMIT)"
