#!/usr/bin/env bash
# Runs `decrypt-list-memory.perf.ts` once per mode, one process each, since WASM memory never
# shrinks. PERF_* variables, e.g. PERF_VAULT_SIZE and PERF_LABEL, pass through. `--expose-gc` lets
# the harness collect garbage before reading the JS heap. PERF_DECRYPT_LIST_MODES picks the modes.
set -eo pipefail

cd "$(dirname "$0")/.."

MODES=${PERF_DECRYPT_LIST_MODES:-eager batched count full-eager full-batched full-count}

for mode in ${MODES}; do
  PERF_DECRYPT_LIST_MODE="${mode}" npx vitest bench --run --execArgv=--expose-gc decrypt-list-memory
done
