// Memory harness: whether iterables that are left early get reclaimed.
//
//   repeat PERF_GC_ITERATIONS times:
//     list_iterable(chunk PERF_GC_CHUNK) over PERF_GC_VAULT ciphers ──► next() once ──► leave
//   every PERF_GC_EVERY iterations: [gc()] ──► macrotask ──► sample memory
//
// An iterable is left one of two ways, set by PERF_GC_MODE:
//   break    `break` out of a `for await`, which calls `return()`
//   abandon  drop the iterator without calling `return()`
//   retain   keep every iterator referenced, without calling `return()`: a deliberate leak, to show
//            what one looks like in the series
//
// The iterator's functions own their Rust state, which is freed once the garbage collector collects
// them and their FinalizationRegistry callbacks run. WASM memory pressure does not trigger garbage
// collection, so with PERF_GC=1 each sample first calls `gc()` twice, each time followed by a
// macrotask for the callbacks; that needs `--expose-gc`, which `perf/iterable-gc.sh` passes. Without
// it the series shows what happens when garbage collection does not run.
//
// A flat linear-memory series after warm-up means the state is reclaimed; steady growth means it
// leaks. Linear memory never shrinks, so a series can only stay flat or grow. Each sample has:
//   wasmMiB      `external - arrayBuffers`, as the other memory harnesses measure
//   memoryMiB    the byte length of the SDK's `WebAssembly.Memory`
//   jsHeapMiB    V8 `heapUsed`, which holds what the leaked state references on the JS side
//
// Env:
//   PERF_GC_MODE        break | abandon | retain                         (default break)
//   PERF_GC             1 to call gc() before each sample                (default 1)
//   PERF_GC_ITERATIONS  iterables created                                (default 2000)
//   PERF_GC_EVERY       iterations between samples                       (default 200)
//   PERF_GC_VAULT       ciphers in the client-managed repository         (default 50)
//   PERF_GC_CHUNK       chunk size                                       (default 10)
//   PERF_LABEL          writes perf/results/<label>/iterable-gc-<mode>[-nogc].json when set

import { wasmMemoryBytes } from "./wasm-memory-probe";

import { ok, strictEqual } from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";

import { test } from "vitest";

import { registerVault } from "./cipher-stream";
import { encryptedVault } from "./decrypt-list-setup";
import { mib, wasmMemory } from "./memory-usage";

const MODE = process.env.PERF_GC_MODE ?? "break";
const GC = (process.env.PERF_GC ?? "1") === "1";
const ITERATIONS = Number(process.env.PERF_GC_ITERATIONS ?? 2000);
const EVERY = Number(process.env.PERF_GC_EVERY ?? 200);
const VAULT_SIZE = Number(process.env.PERF_GC_VAULT ?? 50);
const CHUNK_SIZE = Number(process.env.PERF_GC_CHUNK ?? 10);
const TIMEOUT = 30 * 60_000;

const macrotask = () => new Promise((resolve) => setTimeout(resolve, 0));

async function sample(iteration: number) {
  if (GC) {
    const gc = (globalThis as { gc?: () => void }).gc;
    ok(gc, "PERF_GC=1 needs node --expose-gc");
    for (let round = 0; round < 2; round++) {
      gc();
      await macrotask();
    }
  } else {
    await macrotask();
  }
  return {
    iteration,
    wasmMiB: mib(wasmMemory(), 2),
    memoryMiB: mib(wasmMemoryBytes() ?? Number.NaN, 2),
    jsHeapMiB: mib(process.memoryUsage().heapUsed, 2),
  };
}

test(
  `iterable gc, ${MODE}${GC ? "" : ", no gc"}`,
  async () => {
    ok(["break", "abandon", "retain"].includes(MODE), `unknown PERF_GC_MODE ${MODE}`);
    const { client, ciphers, vault } = await encryptedVault(VAULT_SIZE, VAULT_SIZE);
    await registerVault(client, vault);

    const retained: AsyncIterator<unknown>[] = [];
    const samples = [await sample(0)];
    for (let i = 1; i <= ITERATIONS; i++) {
      const iterable = ciphers.list_iterable(CHUNK_SIZE);
      if (MODE === "break") {
        let read = 0;
        for await (const _view of iterable) {
          read++;
          break;
        }
        strictEqual(read, 1);
      } else {
        const iterator = iterable[Symbol.asyncIterator]();
        const result = await iterator.next();
        strictEqual(result.done, false);
        if (MODE === "retain") {
          retained.push(iterator);
        }
      }
      if (i % EVERY === 0) {
        samples.push(await sample(i));
      }
    }

    console.table(samples);
    strictEqual(retained.length, MODE === "retain" ? ITERATIONS : 0);
    const label = process.env.PERF_LABEL;
    if (label) {
      mkdirSync(`perf/results/${label}`, { recursive: true });
      writeFileSync(
        `perf/results/${label}/iterable-gc-${MODE}${GC ? "" : "-nogc"}.json`,
        JSON.stringify({ mode: MODE, gc: GC, vaultSize: VAULT_SIZE, samples }, null, 2),
      );
    }
  },
  TIMEOUT,
);
