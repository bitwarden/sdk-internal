// Shared tinybench setup and reporting for the performance harnesses.
//
//   makeBench(runs) ──► bench.add(...) ──► bench.run() ──► report(bench, ...)
//                                                            │
//                                       console table ◄──────┼──► perf/results/<file>.json
//                                                            │    (only when PERF_LABEL is set)

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { Bench, type Task } from "tinybench";

const WARMUP_RUNS = 1;

const LABEL = process.env.PERF_LABEL;

const RESULTS_DIR = join(dirname(fileURLToPath(import.meta.url)), "results");

/** Runs each task exactly `runs` times after one warmup run, and rethrows task errors. */
export function makeBench(name: string, runs: number): Bench {
  return new Bench({
    name,
    iterations: runs,
    time: 0,
    warmupIterations: WARMUP_RUNS,
    warmupTime: 0,
    retainSamples: true,
    throws: true,
  });
}

export interface Stats {
  task: string;
  runsMs: number[];
  medianMs: number;
  minMs: number;
  meanMs: number;
  rmePercent: number;
}

function stats(task: Task): Stats {
  const result = task.result;
  if (result.state !== "completed") {
    throw new Error(`${task.name}: ${result.state}`);
  }

  const { latency } = result;
  return {
    task: task.name,
    runsMs: [...(latency.samples ?? [])],
    medianMs: latency.p50,
    minMs: latency.min,
    meanMs: latency.mean,
    rmePercent: latency.rme,
  };
}

/**
 * Prints the bench results and, when `PERF_LABEL` is set, writes them to
 * `perf/results/<LABEL><suffix>.json` with `extra` merged in, e.g. `{ vaultSize: 10000 }`.
 * `columns` adds harness-specific table columns, e.g. µs per cipher.
 */
export function report(
  bench: Bench,
  suffix: string,
  extra: Record<string, unknown> = {},
  columns: (s: Stats) => Record<string, string> = () => ({}),
): void {
  const all = bench.tasks.map(stats);

  console.log(bench.name);
  console.table(
    all.map((s) => ({
      task: s.task,
      "median (ms)": s.medianMs.toFixed(1),
      "min (ms)": s.minMs.toFixed(1),
      "rme (%)": s.rmePercent.toFixed(1),
      ...columns(s),
    })),
  );

  if (!LABEL) {
    return;
  }
  mkdirSync(RESULTS_DIR, { recursive: true });
  const file = join(RESULTS_DIR, `${LABEL}${suffix}.json`);
  writeFileSync(file, JSON.stringify({ label: LABEL, ...extra, stats: all }, null, 2));
}
