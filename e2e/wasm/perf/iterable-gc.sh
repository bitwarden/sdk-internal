#!/usr/bin/env bash
# Runs `iterable-gc.perf.ts` once per mode, with and without gc(), one process each.
#
# `--execArgv=--expose-gc` reaches the vitest worker that runs the harness, which is what makes
# `globalThis.gc` available there. Other PERF_* variables, e.g. PERF_GC_ITERATIONS and PERF_LABEL,
# pass through.
set -eo pipefail

cd "$(dirname "$0")/.."

# Takes the run's variables as `NAME=value` arguments.
run() {
  env "$@" npx vitest bench --run iterable-gc --execArgv=--expose-gc
}

run PERF_GC_MODE=break PERF_GC=1
run PERF_GC_MODE=abandon PERF_GC=1
run PERF_GC_MODE=retain PERF_GC=1
run PERF_GC_MODE=break PERF_GC=0
run PERF_GC_MODE=abandon PERF_GC=0
