#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

# Move to the root of the repository
cd ../../

# Write VERSION file
git rev-parse HEAD > ./crates/bitwarden-wasm-internal/npm/VERSION

if [ "$1" != "-r" ]; then
  echo "Building in debug mode"
  RELEASE_FLAG=""
  BUILD_FOLDER="debug"
else
  echo "Building in release mode"
  RELEASE_FLAG="--release"
  BUILD_FOLDER="release"
fi

# Build normally
cargo build -p bitwarden-wasm-internal --target wasm32-unknown-unknown ${RELEASE_FLAG}
wasm-bindgen --target bundler --out-dir crates/bitwarden-wasm-internal/npm ./target/wasm32-unknown-unknown/${BUILD_FOLDER}/bitwarden_wasm_internal.wasm
wasm-bindgen --target nodejs --out-dir crates/bitwarden-wasm-internal/npm/node ./target/wasm32-unknown-unknown/${BUILD_FOLDER}/bitwarden_wasm_internal.wasm

# Build with MVP CPU target, for wasm2js support
# Note that this requirest build-std which is an unstable feature,
# this normally requires a nightly build, but we can also use the 
# RUSTC_BOOTSTRAP hack to use the same stable version as the normal build
RUSTFLAGS=-Ctarget-cpu=mvp RUSTC_BOOTSTRAP=1 cargo build -p bitwarden-wasm-internal -Zbuild-std=panic_abort,std --target wasm32-unknown-unknown ${RELEASE_FLAG}
cp ./target/wasm32-unknown-unknown/${BUILD_FOLDER}/bitwarden_wasm_internal.wasm ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.mvp.wasm

# Format
npx prettier --write ./crates/bitwarden-wasm-internal/npm

# Optimize size
wasm-opt -Os ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm
wasm-opt -Os ./crates/bitwarden-wasm-internal/npm/node/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/npm/node/bitwarden_wasm_internal_bg.wasm
wasm-opt -Os ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.mvp.wasm -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.mvp.wasm

# Transpile to JS
wasm2js ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.mvp.wasm -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm.js
npx terser ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm.js -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm.js

# Remove unneeded files
rm ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.mvp.wasm
