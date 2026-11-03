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
# Dev-only: exposes the hand-rolled debug-capability tree (client.debug()) to JS.
# Never enable for production builds.
DEBUG_CAPABILITIES_FEATURE=""
# Builds the wasm2js fallback in the background, alongside the SIMD build. Only affects release builds.
PARALLEL=""
# Writes the debug stub instead of the wasm2js fallback, for pull request builds where nothing loads
# the fallback. The MVP binary is still built, to check that it gets the same wasm-bindgen glue.
SKIP_WASM2JS=""

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
    -d)
      DEBUG_CAPABILITIES_FEATURE="--features debug-capabilities"
      ;;
    -p)
      PARALLEL="1"
      ;;
    -s)
      SKIP_WASM2JS="1"
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
  RUSTFLAGS="${cpu} --cfg getrandom_backend=\"wasm_js\" ${NO_COMMERCIAL_CFG}" RUSTC_BOOTSTRAP=1 cargo build -p bitwarden-wasm-internal -Zbuild-std=panic_abort,std --target wasm32-unknown-unknown --target-dir "${target_dir}" ${RELEASE_FLAG} ${ENABLE_LICENSE_FEATURE} ${DEBUG_CAPABILITIES_FEATURE}
}

WASM2JS_STUB='throw new Error("The wasm2js fallback is not included in this build, build with build.sh -r");'

# Builds the MVP binary, then optimizes it for size and transpiles it to JS. The SIMD build doesn't
# depend on any of this, so it can run at the same time.
build_wasm2js() {
  build_wasm "${MVP_CPU}" "${MVP_TARGET_DIR}"
  rm -rf "${MVP_BINDGEN_DIR}"
  cargo run -p wasm-bindgen-cli-runner --bin wasm-bindgen-runner -- --target bundler --out-dir "${MVP_BINDGEN_DIR}" ${MVP_TARGET_DIR}/wasm32-unknown-unknown/${BUILD_FOLDER}/bitwarden_wasm_internal.wasm
  if [ -n "$SKIP_WASM2JS" ]; then
    echo "${WASM2JS_STUB}" > ${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.wasm.js
    return
  fi
  wasm-opt -Os ${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.wasm -o ${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.wasm
  wasm2js -Os ${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.wasm -o ${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.wasm.js
  npx terser ${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.wasm.js -o ${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.wasm.js
}

WASM2JS_PID=""
if [ -n "$RELEASE_FLAG" ] && [ -n "$PARALLEL" ]; then
  # Prefix the output, so the interleaved logs of both builds can be told apart
  (build_wasm2js 2>&1 | awk '{ print "[wasm2js] " $0; fflush() }') &
  WASM2JS_PID=$!
  trap 'kill "${WASM2JS_PID}" 2>/dev/null || true' EXIT
fi

build_wasm "${SIMD_CPU}" ./target

cargo run -p wasm-bindgen-cli-runner --bin wasm-bindgen-runner -- --target bundler --out-dir crates/bitwarden-wasm-internal/${NPM_FOLDER} ./target/wasm32-unknown-unknown/${BUILD_FOLDER}/bitwarden_wasm_internal.wasm
cargo run -p wasm-bindgen-cli-runner --bin wasm-bindgen-runner -- --target nodejs --out-dir crates/bitwarden-wasm-internal/${NPM_FOLDER}/node ./target/wasm32-unknown-unknown/${BUILD_FOLDER}/bitwarden_wasm_internal.wasm
# Format TypeScript definition files only (skip generated .wasm.js files)
npx prettier --write "./crates/bitwarden-wasm-internal/${NPM_FOLDER}/**/*.ts"

# Optimize size, then build the MVP binary and transpile it to JS. Debug builds skip this to save
# build time, and write a stub instead so bundlers importing the fallback still resolve it.
if [ -z "$RELEASE_FLAG" ]; then
  echo "${WASM2JS_STUB}" > ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm.js
else
  # The bundler and nodejs targets usually get the same .wasm file, which only needs optimizing once
  if cmp -s ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/node/bitwarden_wasm_internal_bg.wasm; then
    wasm-opt -Os ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm
    cp ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/node/bitwarden_wasm_internal_bg.wasm
  else
    wasm-opt -Os ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm
    wasm-opt -Os ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/node/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/node/bitwarden_wasm_internal_bg.wasm
  fi

  if [ -n "$WASM2JS_PID" ]; then
    wait "${WASM2JS_PID}"
    trap - EXIT
  else
    build_wasm2js
  fi

  # The wasm2js fallback is loaded through the glue generated for the SIMD build
  if ! cmp -s "${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.js" "crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.js"; then
    echo "error: MVP and SIMD builds produced different wasm-bindgen glue" >&2
    exit 1
  fi

  cp ${MVP_BINDGEN_DIR}/bitwarden_wasm_internal_bg.wasm.js ./crates/bitwarden-wasm-internal/${NPM_FOLDER}/bitwarden_wasm_internal_bg.wasm.js
fi

# Typecheck the generated TypeScript definitions
cd crates/bitwarden-wasm-internal/${NPM_FOLDER}
npm ci
npx tsc --noEmit --lib es2020,dom,ESNext.Disposable bitwarden_wasm_internal.d.ts
