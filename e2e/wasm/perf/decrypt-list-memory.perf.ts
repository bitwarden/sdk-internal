// Memory harness: WASM memory and JS heap growth of `decrypt_list_with_failures` over a large
// vault. See `memory.ts` for what is measured, and `decrypt-list-setup.ts` for the vault. Setup
// encrypts in calls of PERF_SETUP_CHUNK ciphers to keep its own peak small.
//
// Env:
//   PERF_VAULT_SIZE   ciphers in the vault                                (default 12000)
//   PERF_SETUP_CHUNK  ciphers per encrypt_list call during setup          (default 10)
//   PERF_LABEL        writes perf/results/<label>/<task>.json when set

import { strictEqual } from "node:assert/strict";

import { test } from "vitest";

import { encryptedVault } from "./decrypt-list-setup";
import { measureMemory } from "./memory";

const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 12_000);
const SETUP_CHUNK = Number(process.env.PERF_SETUP_CHUNK ?? 10);

test("decrypt_list_with_failures memory", async () => {
  const { ciphers, vault } = await encryptedVault(VAULT_SIZE, SETUP_CHUNK);
  const { result } = await measureMemory(
    "decrypt-list-memory",
    () => ciphers.decrypt_list_with_failures(vault),
    { params: { vaultSize: VAULT_SIZE } },
  );
  strictEqual(result.successes.length, VAULT_SIZE);
});
