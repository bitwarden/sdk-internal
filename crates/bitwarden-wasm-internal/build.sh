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

# Fail the non-commercial build if a bitwarden_license crate leaks in (see bitwarden-commercial-marker).
NO_COMMERCIAL_CFG=""
if [ -z "$ENABLE_LICENSE_FEATURE" ]; then
  NO_COMMERCIAL_CFG="--cfg bitwarden_ensure_non_commercial"
fi

# The shipped .wasm files enable SIMD and other post-MVP features, which make decryption and Argon2
# notably faster. The wasm2js fallback supports MVP only, so it is transpiled from a second, MVP
# build. Both feature sets leave out reference-types and multi-value: those change the JS glue that
# wasm-bindgen generates, and both builds must share one glue file (checked below).
# Note that this requires build-std which is an unstable feature,
# this normally requires a nightly build, but we can also use the
# RUSTC_BOOTSTRAP hack to use the same stable version as the normal build
SIMD_CPU="-Ctarget-cpu=mvp -Ctarget-feature=+simd128,+bulk-memory,+sign-ext,+nontrapping-fptoint,+mutable-globals"
MVP_CPU="-Ctarget-cpu=mvp"
MVP_TARGET_DIR="./target/wasm-mvp"
MVP_BINDGEN_DIR="${MVP_TARGET_DIR}/bindgen"

build_wasm() {
  local cpu="$1"
  local target_dir="$2"
  RUSTFLAGS="${cpu} --cfg getrandom_backend=\"wasm_js\" ${NO_COMMERCIAL_CFG}" RUSTC_BOOTSTRAP=1 cargo build -p bitwarden-wasm-internal -Zbuild-std=panic_abort,std --target wasm32-unknown-unknown --target-dir "${target_dir}" ${RELEASE_FLAG} ${ENABLE_LICENSE_FEATURE}
}

build_wasm "${SIMD_CPU}" ./target
build_wasm "${MVP_CPU}" "${MVP_TARGET_DIR}"

cargo run -p wasm-bindgen-cli-runner --bin wasm-bindgen-runner -- --target bundler --out-dir crates/bitwarden-wasm-internal/${NPM_FOLDER} ./target/wasm32-unknown-unknown/${BUILD_FOLDER}/bitwarden_wasm_internal.wasm
cargo run -p wasm-bindgen-cli-runner --bin wasm-bindgen-runner -- --target nodejs --out-dir crates/bitwarden-wasm-internal/${NPM_FOLDER}/node ./target/wasm32-unknown-unknown/${BUILD_FOLDER}/bitwarden_wasm_internal.wasm
rm -rf "${MVP_BINDGEN_DIR}"
cargo run -p wasm-bindgen-cli-runner --bin wasm-bindgen-runner -- --target bundler --out-dir "${MVP_BINDGEN_DIR}" ${MVP_TARGET_DIR}/wasm32-unknown-unknown/${BUILD_FOLDER}/bitwarden_wasm_internal.wasm

# The wasm2js fallback is loaded through the glue generated for the SIMD build
if ! cmp -s "${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.js" "crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.js"; then
  echo "error: MVP and SIMD builds produced different wasm-bindgen glue" >&2
  exit 1
fi

# Format TypeScript definition files only (skip generated .wasm.js files)
npx prettier --write "./crates/bitwarden-wasm-internal/${NPM_FOLDER}/**/*.ts"

# Optimize size
wasm-opt -Os ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm
wasm-opt -Os ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/node/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/node/bitwarden_wasm_internal_bg.wasm

# Transpile the MVP build to JS
wasm-opt -Os ${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.wasm -o ${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.wasm
wasm2js -Os ${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm.js
if [ -n "$RELEASE_FLAG" ]; then
  npx terser ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm.js -o ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm.js
fi

# Typecheck the generated TypeScript definitions
cd crates/bitwarden-wasm-internal/${NPM_FOLDER}
npm ci
npx tsc --noEmit --lib es2020,dom,ESNext.Disposable bitwarden_wasm_internal.d.ts
