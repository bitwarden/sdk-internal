#!/usr/bin/env bash
# Runs `iterator-memory.perf.ts` once per mode, one process each, since WASM memory never shrinks.
#
# PERF_CHUNK_SIZES sets the comma-separated chunk sizes tried for the iterable (default 50,250,1000).
# Other PERF_* variables, e.g. PERF_VAULT_SIZE and PERF_LABEL, pass through.
set -eo pipefail

cd "$(dirname "$0")/.."

CHUNK_SIZES=${PERF_CHUNK_SIZES:-50,250,1000}

# Takes the mode's variables as `NAME=value` arguments.
run() {
  env "$@" npx vitest bench --run iterator-memory
}

run PERF_STREAM_MODE=array
run PERF_STREAM_MODE=list
for size in ${CHUNK_SIZES//,/ }; do
  run PERF_STREAM_MODE=list-iterable PERF_CHUNK_SIZE="${size}"
done
run PERF_STREAM_MODE=list-iterable-break PERF_CHUNK_SIZE=250
