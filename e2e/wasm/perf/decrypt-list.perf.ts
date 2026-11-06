// Performance harness: decrypting a large vault in one list decrypt call. See
// `decrypt-list-setup.ts` for the vault.
//
//   decrypt_list_with_failures       Cipher[] ──► CipherListView[]
//   decrypt_list_full_with_failures  Cipher[] ──► CipherView[]
//
// Env:
//   PERF_VAULT_SIZE   ciphers in the vault                                (default 12000)
//   PERF_RUNS         timed runs per method                               (default 5)
//   PERF_LABEL        writes perf/results/<label>/<task>.json when set

import { strictEqual } from "node:assert/strict";

import type { Cipher, CiphersClient } from "@bitwarden/sdk-internal";
import { test } from "vitest";

import { benchOptions, runOptions } from "./bench";
import { encryptedVault } from "./decrypt-list-setup";

const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 12_000);
const RUNS = Number(process.env.PERF_RUNS ?? 5);

const METHODS: {
  name: string;
  decrypt: (ciphers: CiphersClient, vault: Cipher[]) => Promise<{ successes: unknown[] }>;
}[] = [
  {
    name: "decrypt_list_with_failures",
    decrypt: (ciphers, vault) => ciphers.decrypt_list_with_failures(vault),
  },
  {
    name: "decrypt_list_full_with_failures",
    decrypt: (ciphers, vault) => ciphers.decrypt_list_full_with_failures(vault),
  },
];

test.for(METHODS)("$name", async ({ name, decrypt }, { bench }) => {
  const { ciphers, vault } = await encryptedVault(VAULT_SIZE, 100);

  // The assertion guards against silently measuring a failing decrypt.
  await bench(name, benchOptions(name), async () => {
    const result = await decrypt(ciphers, vault);
    strictEqual(result.successes.length, VAULT_SIZE);
  }).run(runOptions(`${name}, vault size ${VAULT_SIZE}, ${RUNS} runs`, RUNS));
});
