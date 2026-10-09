// Shared vitest bench options for the performance harnesses.
//
//   test(..., ({ bench }) ──► bench(name, benchOptions(task), fn) ──► bench.compare(..., runOptions(runs))
//                                       │
//                                       └──► perf/results/<label>/<task>.json (only when PERF_LABEL is set)

import type { BenchFnOptions, BenchRunOptions } from "vitest";

const WARMUP_RUNS = 1;

const LABEL = process.env.PERF_LABEL;

/** Runs each task exactly `runs` times after one warmup run. */
export function runOptions(name: string, runs: number): BenchRunOptions {
  return { name, iterations: runs, time: 0, warmupIterations: WARMUP_RUNS, warmupTime: 0 };
}

/** Writes the task result to `perf/results/<LABEL>/<task>.json` when `PERF_LABEL` is set. */
export function benchOptions(task: string): BenchFnOptions {
  return LABEL ? { writeResult: `perf/results/${LABEL}/${task}.json` } : {};
}
