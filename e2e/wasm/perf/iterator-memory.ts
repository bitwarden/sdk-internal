// Shared by the iterator memory harnesses, one file per mode: WASM memory and JS heap growth while
// listing a large vault in one call or through the iterable. See `memory.ts` for what is measured.
//
//   setup: generateVault ──► encrypt_list (PERF_SETUP_CHUNK ciphers per call) ──► Cipher[]
//                                                                          │
//          client-managed cipher repository ◄──────────────────────────────┤
//                                                                          │
//   measured:                               decrypt in mode ◄──────────────┘
//
// Setup encrypts in chunks of PERF_SETUP_CHUNK ciphers to keep its own peak small. See
// `cipher-stream.ts` for the modes; `list-iterable-break` is measured after the break, with the
// rest of the vault never converted.
//
// Env:
//   PERF_CHUNK_SIZE   ciphers per chunk of the iterable                       (default 250)
//   PERF_VAULT_SIZE   ciphers in the vault                                    (default 12000)
//   PERF_SETUP_CHUNK  ciphers per encrypt_list call during setup              (default 10)
//   PERF_LABEL        writes perf/results/<label>/iterator-memory-<mode>.json when set

import { strictEqual } from "node:assert/strict";

import { test } from "vitest";

import { decryptVault, expectedReads, registerVault, type StreamMode } from "./cipher-stream";
import { encryptedVault } from "./decrypt-list-setup";
import { measureMemory } from "./memory";

const CHUNK_SIZE = Number(process.env.PERF_CHUNK_SIZE ?? 250);
const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 12_000);
const SETUP_CHUNK = Number(process.env.PERF_SETUP_CHUNK ?? 10);

/** Declares the memory harness of `mode`. A harness file declares one. */
export function iteratorMemoryTest(mode: StreamMode): void {
  const iterable = mode.startsWith("list-iterable");
  test(`iterator memory, ${mode}`, async () => {
    const { client, ciphers, vault } = await encryptedVault(VAULT_SIZE, SETUP_CHUNK);
    await registerVault(client, vault);

    const { result } = await measureMemory(
      `iterator-memory-${iterable ? `${mode}-${CHUNK_SIZE}` : mode}`,
      () => decryptVault(ciphers, vault, mode, CHUNK_SIZE),
      { params: { mode, chunkSize: iterable ? CHUNK_SIZE : VAULT_SIZE, vaultSize: VAULT_SIZE } },
    );
    strictEqual(result.failures, 0);
    strictEqual(result.views.length, expectedReads(mode, VAULT_SIZE));
  });
}
