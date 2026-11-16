// Memory measurement for the performance harnesses, the counterpart of `bench.ts` for timings.
//
//   setup ──► measureMemory(name, fn) ──► [gc] ──► fn() ──► [gc] ──► WASM and JS heap growth
//                                                                        │
//                                         perf/results/<label>/<name>.json (only when PERF_LABEL is set)
//
// WASM linear memory never shrinks, so its growth over `fn` is the peak memory the SDK needed for
// it, but only if nothing earlier in the process grew it further. Measure once per process: vitest
// runs each harness file in its own process, so a harness file holds a single `measureMemory` call.
// Growth that setup already caused is invisible to `fn`, so keep the peak of setup small; the
// result reports it as `setupMiB`.
//
// The wasm-bindgen Node output does not export the SDK's `WebAssembly.Memory`. This module wraps
// `WebAssembly.Instance` to capture it, so it has to load before the SDK does. In benchmark mode,
// which `npm run perf` selects, the vitest config lists this module in `setupFiles` and passes
// `--expose-gc` to the harness processes, which `collectGarbage` needs.

import { ok } from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";

const MiB = 1024 * 1024;
const LABEL = process.env.PERF_LABEL;

interface Probe {
  memory?: WebAssembly.Memory;
  /** The byte length of the memory when the SDK was instantiated. */
  initialBytes?: number;
  measured: boolean;
}

// On `globalThis`, so the probe is shared even if the setup file and a harness load this module
// as separate instances.
const PROBE_KEY = Symbol.for("bitwarden.perf.memoryProbe");
const globals = globalThis as { [PROBE_KEY]?: Probe };
const probe: Probe = (globals[PROBE_KEY] ??= installProbe());

function installProbe(): Probe {
  const state: Probe = { measured: false };
  const Instance = WebAssembly.Instance;
  WebAssembly.Instance = new Proxy(Instance, {
    construct(target, args, newTarget) {
      const instance = Reflect.construct(target, args, newTarget) as WebAssembly.Instance;
      if (state.memory === undefined) {
        state.memory = Object.values(instance.exports).find(
          (value): value is WebAssembly.Memory => value instanceof WebAssembly.Memory,
        );
        state.initialBytes = state.memory?.buffer.byteLength;
      }
      return instance;
    },
  });
  return state;
}

/** `bytes` in MiB, rounded to `digits` decimals. */
export function mib(bytes: number, digits = 1): number {
  return Number((bytes / MiB).toFixed(digits));
}

/** The byte length of the SDK's linear memory. Fails before the SDK is loaded. */
export function wasmMemoryBytes(): number {
  ok(
    probe.memory,
    "the SDK's WebAssembly.Memory was not captured; run the harness with npm run perf",
  );
  return probe.memory.buffer.byteLength;
}

const macrotask = () => new Promise((resolve) => setTimeout(resolve, 0));

/**
 * Runs two full garbage collections, each followed by a macrotask so that FinalizationRegistry
 * callbacks, which free the Rust side of collected wasm-bindgen objects, get to run.
 */
export async function collectGarbage(): Promise<void> {
  const gc = globalThis.gc;
  ok(gc, "gc is not exposed; run the harness with npm run perf");
  for (let round = 0; round < 2; round++) {
    gc();
    await macrotask();
  }
}

/** A reading of the SDK's linear memory and the JS heap, in MiB. */
export interface MemorySample {
  wasmMiB: number;
  jsHeapMiB: number;
}

/** Reads the SDK's linear memory and the JS heap, after collecting garbage when `gc` is set. */
export async function sampleMemory({ gc = true }: { gc?: boolean } = {}): Promise<MemorySample> {
  if (gc) {
    await collectGarbage();
  } else {
    await macrotask();
  }
  return {
    wasmMiB: mib(wasmMemoryBytes(), 2),
    jsHeapMiB: mib(process.memoryUsage().heapUsed, 2),
  };
}

/** Writes `data` to `perf/results/<LABEL>/<name>.json` when `PERF_LABEL` is set. */
export function writeResult(name: string, data: unknown): void {
  if (LABEL) {
    mkdirSync(`perf/results/${LABEL}`, { recursive: true });
    writeFileSync(`perf/results/${LABEL}/${name}.json`, JSON.stringify(data, null, 2));
  }
}

/** Options of `measureMemory`. */
export interface MemoryOptions {
  /** What the measurement ran with, such as the vault size; reported with the result. */
  params?: Record<string, string | number | boolean>;
}

/** What `measureMemory` reports, in MiB, after the `params` it was given. */
export interface MemoryResult {
  task: string;
  /** Linear memory that setup grew before `fn` ran, which hides growth of `fn` up to that size. */
  setupMiB: number;
  /** Linear memory when `fn` started. */
  wasmBeforeMiB: number;
  /** Linear memory growth over `fn`: the peak the SDK needed beyond what setup had grown. */
  wasmGrowthMiB: number;
  /** JS heap growth over `fn` with its result still held, between two full collections. */
  jsHeapGrowthMiB: number;
}

/**
 * Measures the growth of the SDK's linear memory and of the JS heap over `fn`, keeping what `fn`
 * returns reachable until both are read. Prints the result, with `options.params`, as a table and
 * writes it to `perf/results/<LABEL>/<name>.json` when `PERF_LABEL` is set.
 *
 * Fails when called a second time in the same process, where the first call's growth would hide
 * that of the second.
 */
export async function measureMemory<T>(
  name: string,
  fn: () => Promise<T>,
  { params = {} }: MemoryOptions = {},
): Promise<MemoryResult & { result: T }> {
  ok(!probe.measured, "measureMemory runs once per process; put each measurement in its own file");
  probe.measured = true;

  await collectGarbage();
  const wasmBefore = wasmMemoryBytes();
  const heapBefore = process.memoryUsage().heapUsed;

  const result = await fn();

  await collectGarbage();
  const wasmAfter = wasmMemoryBytes();
  const heapAfter = process.memoryUsage().heapUsed;

  const stats = {
    task: name,
    ...params,
    setupMiB: mib(wasmBefore - (probe.initialBytes ?? wasmBefore)),
    wasmBeforeMiB: mib(wasmBefore),
    wasmGrowthMiB: mib(wasmAfter - wasmBefore),
    jsHeapGrowthMiB: mib(heapAfter - heapBefore),
  };
  console.table([stats]);
  writeResult(name, stats);
  return { ...stats, result };
}
