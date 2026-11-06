// Shared by the iterable gc harnesses, one file per mode: whether iterables that are left early get
// reclaimed.
//
//   repeat PERF_GC_ITERATIONS times:
//     list_iterable(chunk PERF_GC_CHUNK) over PERF_GC_VAULT ciphers ──► next() once ──► leave
//   every PERF_GC_EVERY iterations: [collectGarbage()] ──► sampleMemory()
//
// The mode sets how an iterable is left:
//   break    `break` out of a `for await`, which calls `return()`
//   abandon  drop the iterator without calling `return()`
//   retain   keep every iterator referenced, without calling `return()`: a deliberate leak, to show
//            what one looks like in the series
//
// The iterator's functions own their Rust state, which is freed once the garbage collector collects
// them and their FinalizationRegistry callbacks run. WASM memory pressure does not trigger garbage
// collection, so with PERF_GC=1 each sample first collects garbage (see `collectGarbage` in
// `memory.ts`). PERF_GC=0 shows what happens when garbage collection does not run.
//
// A flat linear-memory series after warm-up means the state is reclaimed; steady growth means it
// leaks. Linear memory never shrinks, so a series can only stay flat or grow, and each mode runs in
// its own process. Each sample has:
//   wasmMiB      the byte length of the SDK's `WebAssembly.Memory`
//   jsHeapMiB    V8 `heapUsed`, which holds what the leaked state references on the JS side
//
// Env:
//   PERF_GC             1 to collect garbage before each sample          (default 1)
//   PERF_GC_ITERATIONS  iterables created                                (default 2000)
//   PERF_GC_EVERY       iterations between samples                       (default 200)
//   PERF_GC_VAULT       ciphers in the client-managed repository         (default 50)
//   PERF_GC_CHUNK       chunk size                                       (default 10)
//   PERF_LABEL          writes perf/results/<label>/iterable-gc-<mode>[-nogc].json when set

import { strictEqual } from "node:assert/strict";

import { test } from "vitest";

import { registerVault } from "./cipher-stream";
import { encryptedVault } from "./decrypt-list-setup";
import { sampleMemory, writeResult } from "./memory";

export type IterableGcMode = "break" | "abandon" | "retain";

const GC = (process.env.PERF_GC ?? "1") === "1";
const ITERATIONS = Number(process.env.PERF_GC_ITERATIONS ?? 2000);
const EVERY = Number(process.env.PERF_GC_EVERY ?? 200);
const VAULT_SIZE = Number(process.env.PERF_GC_VAULT ?? 50);
const CHUNK_SIZE = Number(process.env.PERF_GC_CHUNK ?? 10);
const TIMEOUT = 30 * 60_000;

async function sample(iteration: number) {
  return { iteration, ...(await sampleMemory({ gc: GC })) };
}

/** Declares the iterable gc harness of `mode`. A harness file declares one. */
export function iterableGcTest(mode: IterableGcMode): void {
  test(
    `iterable gc, ${mode}${GC ? "" : ", no gc"}`,
    async () => {
      const { client, ciphers, vault } = await encryptedVault(VAULT_SIZE, VAULT_SIZE);
      await registerVault(client, vault);

      const retained: AsyncIterator<unknown>[] = [];
      const samples = [await sample(0)];
      for (let i = 1; i <= ITERATIONS; i++) {
        const iterable = ciphers.list_iterable(CHUNK_SIZE);
        if (mode === "break") {
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
          if (mode === "retain") {
            retained.push(iterator);
          }
        }
        if (i % EVERY === 0) {
          samples.push(await sample(i));
        }
      }

      console.table(samples);
      strictEqual(retained.length, mode === "retain" ? ITERATIONS : 0);
      writeResult(`iterable-gc-${mode}${GC ? "" : "-nogc"}`, {
        mode,
        gc: GC,
        vaultSize: VAULT_SIZE,
        samples,
      });
    },
    TIMEOUT,
  );
}
