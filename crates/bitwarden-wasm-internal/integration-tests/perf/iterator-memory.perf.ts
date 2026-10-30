// Memory harness: WASM memory growth while decrypting a large vault in one call or through a stream.
//
//   setup: generateVault ──► encrypt_list (PERF_SETUP_CHUNK ciphers per call) ──► Cipher[]
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
// could hide under. See `cipher-stream.ts` for the modes; `iterable-results-break` is measured after the
// break, with the rest of the vault never pulled.
//
// Env:
//   PERF_STREAM_MODE  a mode from `cipher-stream.ts`, e.g. chunk               (default array)
//   PERF_CHUNK_SIZE   ciphers per call in the chunk modes                     (default 250)
//   PERF_VAULT_SIZE   ciphers in the vault                                    (default 12000)
//   PERF_SETUP_CHUNK  ciphers per encrypt_list call during setup              (default 10)
//   PERF_LABEL        writes perf/results/<label>/iterator-memory-<mode>.json when set

import { ok, strictEqual } from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";

import type { Cipher } from "@bitwarden/sdk-internal";
import { test } from "vitest";

import { makeStateBridge, makeV2AccountClient } from "../tests/utils";

import {
  decryptVault,
  expectedReads,
  isItemMode,
  STREAM_MODES,
  type StreamMode,
} from "./cipher-stream";
import { generateVault } from "./vault-generator";

const MODE = (process.env.PERF_STREAM_MODE ?? "array") as StreamMode;
const CHUNK_SIZE = Number(process.env.PERF_CHUNK_SIZE ?? 250);
const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 12_000);
const SETUP_CHUNK = Number(process.env.PERF_SETUP_CHUNK ?? 10);
const CIPHER_KEY_FLAG = "enableCipherKeyEncryption";
const MiB = 1024 * 1024;

/** WASM memory plus other non-ArrayBuffer external memory, in bytes. */
function wasmMemory(): number {
  const { external, arrayBuffers } = process.memoryUsage();
  return external - arrayBuffers;
}

const mib = (bytes: number) => Number((bytes / MiB).toFixed(1));

test(`iterator memory, ${MODE}`, async () => {
  ok(STREAM_MODES.includes(MODE), `unknown PERF_STREAM_MODE ${MODE}`);
  const chunkSize = isItemMode(MODE) ? 1 : CHUNK_SIZE;

  const initial = wasmMemory();
  const client = await makeV2AccountClient(makeStateBridge());
  await client.platform().load_flags(new Map([[CIPHER_KEY_FLAG, true]]));
  const ciphers = client.vault().ciphers();

  const plaintext = generateVault(VAULT_SIZE);
  const vault: Cipher[] = [];
  for (let i = 0; i < plaintext.length; i += SETUP_CHUNK) {
    const encrypted = await ciphers.encrypt_list(plaintext.slice(i, i + SETUP_CHUNK));
    vault.push(...encrypted.map((ctx) => ctx.cipher));
  }
  ok(vault.every((cipher) => cipher.key !== undefined));
  const before = wasmMemory();

  const { views, failures } = await decryptVault(ciphers, vault, MODE, chunkSize);
  strictEqual(failures, 0);
  strictEqual(views.length, expectedReads(MODE, VAULT_SIZE));

  const growth = wasmMemory() - before;
  const stats = {
    task: "iterator-memory",
    mode: MODE,
    chunkSize: MODE === "array" ? VAULT_SIZE : chunkSize,
    vaultSize: VAULT_SIZE,
    setupMiB: mib(before - initial),
    baselineMiB: mib(before),
    growthMiB: mib(growth),
  };
  console.table([stats]);
  const label = process.env.PERF_LABEL;
  if (label) {
    const name = MODE === "array" || isItemMode(MODE) ? MODE : `${MODE}-${chunkSize}`;
    mkdirSync(`perf/results/${label}`, { recursive: true });
    writeFileSync(
      `perf/results/${label}/iterator-memory-${name}.json`,
      JSON.stringify(stats, null, 2),
    );
  }
});
