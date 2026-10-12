#!/usr/bin/env bash
# Release build of the Node target only, for performance runs.
#
# Mirrors `../../build.sh -r` but keeps the wasm `names` section (`wasm-opt -g`) so CPU profiles
# show Rust symbols instead of `wasm-function[1234]`. Names do not change generated code.
#
# PERF_WASM_CPU overrides the wasm target features, e.g.
#   PERF_WASM_CPU="-Ctarget-cpu=mvp" ./perf/build.sh
# PERF_CARGO_ARGS adds cargo flags, e.g. per-crate opt-level overrides
#   PERF_CARGO_ARGS="--config profile.release.package.argon2.opt-level=3" ./perf/build.sh
set -eo pipefail

# Default matches the shipped .wasm in `../../build.sh`.
WASM_CPU=${PERF_WASM_CPU:--Ctarget-cpu=mvp -Ctarget-feature=+simd128,+bulk-memory,+sign-ext,+nontrapping-fptoint,+mutable-globals}

cd "$(dirname "$0")/../../../.."

OUT=crates/bitwarden-wasm-internal/npm/node
WASM=./target/wasm32-unknown-unknown/release/bitwarden_wasm_internal.wasm

RUSTFLAGS="${WASM_CPU} --cfg getrandom_backend=\"wasm_js\" --cfg bitwarden_ensure_non_commercial" \
  RUSTC_BOOTSTRAP=1 cargo build -p bitwarden-wasm-internal -Zbuild-std=panic_abort,std \
  --target wasm32-unknown-unknown --release ${PERF_CARGO_ARGS}

cargo run -q -p wasm-bindgen-cli-runner --bin wasm-bindgen-runner -- --target nodejs --out-dir ${OUT} ${WASM}
wasm-opt -Os -g ${OUT}/bitwarden_wasm_internal_bg.wasm -o ${OUT}/bitwarden_wasm_internal_bg.wasm
