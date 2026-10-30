// Memory harness: WASM memory growth while listing a large vault in one call or through the iterable.
//
//   setup: generateVault ──► encrypt_list (PERF_SETUP_CHUNK ciphers per call) ──► Cipher[]
//                                                                          │
//          client-managed cipher repository ◄──────────────────────────────┤
//                                                                          │
//   measured:                    decrypt in PERF_STREAM_MODE ◄─────────────┘
//
// WASM linear memory never shrinks, so its growth over the decrypt is the peak memory the SDK
// needed for it. Node counts WASM memory in `external` but not in `arrayBuffers`, so their
// difference excludes the JS copies of the ciphers and views. Vitest runs each harness file in its
// own process; this file holds a single case so earlier modes cannot have grown the memory already.
// Run one process per mode, as `perf/iterator-memory.sh` does.
//
// Client creation, vault generation and encryption are outside the measured window. Encryption
// still grows linear memory, and growth that setup already caused is invisible to the decrypt, so
// setup encrypts in chunks of PERF_SETUP_CHUNK ciphers to keep its own peak small. The baseline is
// taken after setup; `setupMiB` reports what setup grew, as an upper bound on what a small mode
// could hide under. See `cipher-stream.ts` for the modes; `list-iterable-break` is measured after
// the break, with the rest of the vault never converted.
//
// Env:
//   PERF_STREAM_MODE  a mode from `cipher-stream.ts`, e.g. list-iterable       (default list)
//   PERF_CHUNK_SIZE   ciphers per chunk of the iterable                       (default 250)
//   PERF_VAULT_SIZE   ciphers in the vault                                    (default 12000)
//   PERF_SETUP_CHUNK  ciphers per encrypt_list call during setup              (default 10)
//   PERF_LABEL        writes perf/results/<label>/iterator-memory-<mode>.json when set

import { ok, strictEqual } from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";

import { test } from "vitest";

import {
  decryptVault,
  expectedReads,
  registerVault,
  STREAM_MODES,
  type StreamMode,
} from "./cipher-stream";
import { encryptedVault } from "./decrypt-list-setup";
import { mib, wasmMemory } from "./memory-usage";

const MODE = (process.env.PERF_STREAM_MODE ?? "list") as StreamMode;
const CHUNK_SIZE = Number(process.env.PERF_CHUNK_SIZE ?? 250);
const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 12_000);
const SETUP_CHUNK = Number(process.env.PERF_SETUP_CHUNK ?? 10);

test(`iterator memory, ${MODE}`, async () => {
  ok(STREAM_MODES.includes(MODE), `unknown PERF_STREAM_MODE ${MODE}`);

  const initial = wasmMemory();
  const { client, ciphers, vault } = await encryptedVault(VAULT_SIZE, SETUP_CHUNK);
  await registerVault(client, vault);
  const before = wasmMemory();

  const { views, failures } = await decryptVault(ciphers, vault, MODE, CHUNK_SIZE);
  strictEqual(failures, 0);
  strictEqual(views.length, expectedReads(MODE, VAULT_SIZE));

  const growth = wasmMemory() - before;
  const stats = {
    task: "iterator-memory",
    mode: MODE,
    chunkSize: MODE.startsWith("list-iterable") ? CHUNK_SIZE : VAULT_SIZE,
    vaultSize: VAULT_SIZE,
    setupMiB: mib(before - initial),
    baselineMiB: mib(before),
    growthMiB: mib(growth),
  };
  console.table([stats]);
  const label = process.env.PERF_LABEL;
  if (label) {
    const name = MODE.startsWith("list-iterable") ? `${MODE}-${CHUNK_SIZE}` : MODE;
    mkdirSync(`perf/results/${label}`, { recursive: true });
    writeFileSync(
      `perf/results/${label}/iterator-memory-${name}.json`,
      JSON.stringify(stats, null, 2),
    );
  }
});
