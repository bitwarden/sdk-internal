// Memory harness: WASM memory growth while decrypting a large vault in one list decrypt call, in
// PERF_DECRYPT_LIST_MODE. See `decrypt-list-setup.ts`.
//
// Modes, for `CipherListView` output and with a `full-` prefix for `CipherView` output:
//   eager    `_eager` baseline   input converted in full at the boundary, output built in full
//   batched  the real method     input converted a batch at a time, output built in full
//   count    `_count` baseline   input converted a batch at a time, each result dropped
// So `batched - count` is what the output takes, and `eager - batched` what batched input saves.
//
// WASM linear memory never shrinks, so its growth over the decrypt is the peak memory the SDK
// needed for it. Node counts WASM memory in `external` but not in `arrayBuffers`, so their
// difference excludes the JS copies of the ciphers and views. Vitest runs each harness file in its
// own process; this file holds a single case so the other mode cannot have grown the memory
// already. Run one process per mode, as `perf/decrypt-list-memory.sh` does.
//
// Setup still grows linear memory, and growth that setup already caused is invisible to the
// decrypt, so setup encrypts in calls of PERF_SETUP_CHUNK ciphers to keep its own peak small.
// `setupMiB` reports what setup grew, as an upper bound on what a small mode could hide under.
//
// `heapGrowthMiB` is the JS heap growth over the decrypt with its result still held, where the
// returned views live in every mode but `count`. It is exact only when `gc` is exposed
// (`--expose-gc`, as `perf/decrypt-list-memory.sh` passes); otherwise it includes garbage.
//
// Env:
//   PERF_DECRYPT_LIST_MODE  a mode above                                       (default batched)
//   PERF_VAULT_SIZE         ciphers in the vault                              (default 12000)
//   PERF_SETUP_CHUNK        ciphers per encrypt_list call during setup        (default 10)
//   PERF_LABEL              writes perf/results/<label>/decrypt-list-memory-<mode>.json when set

import { ok, strictEqual } from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";

import type { Cipher, CiphersClient } from "@bitwarden/sdk-internal";
import { test } from "vitest";

import {
  type CiphersPerfBaselines,
  decryptFullList,
  decryptList,
  encryptedVault,
} from "./decrypt-list-setup";

type Client = CiphersClient & CiphersPerfBaselines;

/** Each mode's decrypt, resolving to what it returns and its number of successes. */
const MODES: Record<string, (ciphers: Client, vault: Cipher[]) => Promise<[unknown, number]>> = {
  eager: async (c, v) => withCount(await decryptList(c, v, "eager")),
  batched: async (c, v) => withCount(await decryptList(c, v, "batched")),
  count: async (c, v) => [null, await c.decrypt_list_with_failures_count(v)],
  "full-eager": async (c, v) => withCount(await decryptFullList(c, v, "eager")),
  "full-batched": async (c, v) => withCount(await decryptFullList(c, v, "batched")),
  "full-count": async (c, v) => [null, await c.decrypt_list_full_with_failures_count(v)],
};

function withCount<R extends { successes: unknown[] }>(result: R): [R, number] {
  return [result, result.successes.length];
}

const MODE = process.env.PERF_DECRYPT_LIST_MODE ?? "batched";
const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 12_000);
const SETUP_CHUNK = Number(process.env.PERF_SETUP_CHUNK ?? 10);
const MiB = 1024 * 1024;

/** WASM memory plus other non-ArrayBuffer external memory, in bytes. */
function wasmMemory(): number {
  const { external, arrayBuffers } = process.memoryUsage();
  return external - arrayBuffers;
}

/** JS heap in use, in bytes, after a full collection when `gc` is exposed. */
function jsHeap(): number {
  globalThis.gc?.();
  return process.memoryUsage().heapUsed;
}

const mib = (bytes: number) => Number((bytes / MiB).toFixed(1));

test(`decrypt list memory, ${MODE}`, async () => {
  const decrypt = MODES[MODE];
  ok(decrypt, `unknown PERF_DECRYPT_LIST_MODE ${MODE}`);

  const initial = wasmMemory();
  const { ciphers, vault } = await encryptedVault(VAULT_SIZE, SETUP_CHUNK);
  const before = wasmMemory();
  const heapBefore = jsHeap();

  const [result, successes] = await decrypt(ciphers, vault);
  const growth = wasmMemory() - before;
  const heapGrowth = jsHeap() - heapBefore;
  strictEqual(successes, VAULT_SIZE);

  const stats = {
    task: "decrypt-list-memory",
    mode: MODE,
    vaultSize: VAULT_SIZE,
    setupMiB: mib(before - initial),
    baselineMiB: mib(before),
    growthMiB: mib(growth),
    heapGrowthMiB: mib(heapGrowth),
    gcExposed: globalThis.gc !== undefined,
  };
  console.table([stats]);
  // Keeps the result reachable until after the heap was measured.
  ok(result !== undefined);
  const label = process.env.PERF_LABEL;
  if (label) {
    mkdirSync(`perf/results/${label}`, { recursive: true });
    writeFileSync(
      `perf/results/${label}/decrypt-list-memory-${MODE}.json`,
      JSON.stringify(stats, null, 2),
    );
  }
});
