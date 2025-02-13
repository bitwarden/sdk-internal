#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

# Move to the root of the repository
cd ../../

# Write VERSION file
git rev-parse HEAD > ./crates/bitwarden-wasm-internal/npm/VERSION

if [ "$1" != "-r" ]; then
  # Dev
  cargo build -p bitwarden-wasm-internal --target wasm32-unknown-unknown --release --config 'patch.crates-io.pkcs5.git="https://github.com/bitwarden/rustcrypto-formats.git"'  --config 'patch.crates-io.pkcs5.rev="2b27c63034217dd126bbf5ed874da51b84f8c705"'
  wasm-bindgen --target bundler --out-dir crates/bitwarden-wasm-internal/npm ./target/wasm32-unknown-unknown/debug/bitwarden_wasm_internal.wasm
  wasm-bindgen --target nodejs --out-dir crates/bitwarden-wasm-internal/npm/node ./target/wasm32-unknown-unknown/debug/bitwarden_wasm_internal.wasm
else
  # Release
  cargo build -p bitwarden-wasm-internal --target wasm32-unknown-unknown --release --config 'patch.crates-io.pkcs5.git="https://github.com/bitwarden/rustcrypto-formats.git"'  --config 'patch.crates-io.pkcs5.rev="2b27c63034217dd126bbf5ed874da51b84f8c705"'
  wasm-bindgen --target bundler --out-dir crates/bitwarden-wasm-internal/npm ./target/wasm32-unknown-unknown/release/bitwarden_wasm_internal.wasm
  wasm-bindgen --target nodejs --out-dir crates/bitwarden-wasm-internal/npm/node ./target/wasm32-unknown-unknown/release/bitwarden_wasm_internal.wasm
fi

# Format
npx prettier --write ./crates/bitwarden-wasm-internal/npm

# Optimize size
wasm-opt -Os ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm

# Transpile to JS
wasm2js ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm.js
npx terser ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm.js -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm.js
