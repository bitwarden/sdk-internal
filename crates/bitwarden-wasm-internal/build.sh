#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

# Move to the root of the repository
cd ../../

# Write VERSION file
git rev-parse HEAD > ./crates/bitwarden-wasm-internal/npm/VERSION


# Parse flags
ENABLE_LICENSE_FEATURE=""
NPM_FOLDER="npm"
RELEASE_FLAG=""
BUILD_FOLDER="debug"

while [[ $# -gt 0 ]]; do
  case "$1" in
    -b)
      ENABLE_LICENSE_FEATURE="--features bitwarden-license"
      NPM_FOLDER="bitwarden_license/npm"
      ;;
    -r)
      RELEASE_FLAG="--release"
      BUILD_FOLDER="release"
      ;;
  esac
  shift
done

if [ -n "$RELEASE_FLAG" ]; then
  echo "Building in release mode"
else
  echo "Building in debug mode"
fi

if [ -n "$ENABLE_LICENSE_FEATURE" ]; then
  echo "Build will include BITWARDEN LICENSED FEATURES"
fi

# Build with MVP CPU target, two reasons:
# 1. It is required for wasm2js support
# 2. While webpack supports it, it has some compatibility issues that lead to strange results
# Note that this requirest build-std which is an unstable feature,
# this normally requires a nightly build, but we can also use the
# RUSTC_BOOTSTRAP hack to use the same stable version as the normal build
RUSTFLAGS=-Ctarget-cpu=mvp RUSTC_BOOTSTRAP=1 cargo build -p bitwarden-wasm-internal -Zbuild-std=panic_abort,std --target wasm32-unknown-unknown ${RELEASE_FLAG} ${ENABLE_LICENSE_FEATURE}
wasm-bindgen --target bundler --out-dir crates/bitwarden-wasm-internal/${NPM_FOLDER} ./target/wasm32-unknown-unknown/${BUILD_FOLDER}/bitwarden_wasm_internal.wasm
wasm-bindgen --target nodejs --out-dir crates/bitwarden-wasm-internal/${NPM_FOLDER}/node ./target/wasm32-unknown-unknown/${BUILD_FOLDER}/bitwarden_wasm_internal.wasm

# Format
npx prettier --write ./crates/bitwarden-wasm-internal/${NPM_FOLDER}

# Optimize size
wasm-opt -Os ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm
wasm-opt -Os ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/node/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/node/bitwarden_wasm_internal_bg.wasm

# Transpile to JS
wasm2js -Os ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm.js
npx terser ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm.js -o ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm.js

# Typecheck the generated TypeScript definitions
cd crates/bitwarden-wasm-internal/${NPM_FOLDER}
npx tsc --noEmit --lib es2020,dom bitwarden_wasm_internal.d.ts
