// Performance harness: decrypting a large vault with its `Cipher[]` converted in full at the
// boundary (eager) or a batch at a time inside the SDK (batched). See `decrypt-list-setup.ts`. A
// second case times both for `decrypt_list_full_with_failures`, which returns full `CipherView`s.
//
// Before timing, every result is checked to equal the eager one, and to have its object keys in
// the same order at every level.
//
// Env:
//   PERF_VAULT_SIZE   ciphers in the vault                                (default 12000)
//   PERF_RUNS         timed runs per task                                 (default 5)
//   PERF_LABEL        writes perf/results/<label>/<task>.json when set

import { deepStrictEqual, strictEqual } from "node:assert/strict";

import type { DecryptCipherListResult, DecryptCipherResult } from "@bitwarden/sdk-internal";
import { test } from "vitest";

import { benchOptions, runOptions } from "./bench";
import {
  DECRYPT_LIST_MODES,
  decryptFullList,
  decryptList,
  encryptedVault,
} from "./decrypt-list-setup";

const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 12_000);
const RUNS = Number(process.env.PERF_RUNS ?? 5);

/**
 * Asserts `actual` equals `expected`, with the same object keys in the same order at every level.
 * `deepStrictEqual` ignores key order and `JSON.stringify` follows it, so the two together do.
 */
function assertSame(actual: unknown, expected: unknown) {
  deepStrictEqual(actual, expected);
  strictEqual(JSON.stringify(actual), JSON.stringify(expected));
}

test("decrypt list", async ({ bench }) => {
  const { ciphers, vault } = await encryptedVault(VAULT_SIZE, 100);

  const tasks: { name: string; decrypt: () => Promise<DecryptCipherListResult> }[] =
    DECRYPT_LIST_MODES.map((mode) => ({
      name: mode,
      decrypt: () => decryptList(ciphers, vault, mode),
    }));

  const eager = await decryptList(ciphers, vault, "eager");
  strictEqual(eager.successes.length, VAULT_SIZE);
  for (const { decrypt } of tasks) {
    assertSame(await decrypt(), eager);
  }

  // Assertions guard against silently measuring a failing decrypt.
  await bench.compare(
    ...tasks.map(({ name, decrypt }) => {
      const task = `decrypt_list_with_failures ${name}`;
      return bench(task, benchOptions(task), async () => {
        const result = await decrypt();
        strictEqual(result.successes.length, VAULT_SIZE);
      });
    }),
    runOptions(`decrypt list, vault size ${VAULT_SIZE}, ${RUNS} runs`, RUNS),
  );
});

test("decrypt full list", async ({ bench }) => {
  const { ciphers, vault } = await encryptedVault(VAULT_SIZE, 100);

  const tasks: { name: string; decrypt: () => Promise<DecryptCipherResult> }[] =
    DECRYPT_LIST_MODES.map((mode) => ({
      name: mode,
      decrypt: () => decryptFullList(ciphers, vault, mode),
    }));

  const eager = await decryptFullList(ciphers, vault, "eager");
  strictEqual(eager.successes.length, VAULT_SIZE);
  for (const { decrypt } of tasks) {
    assertSame(await decrypt(), eager);
  }

  // Assertions guard against silently measuring a failing decrypt.
  await bench.compare(
    ...tasks.map(({ name, decrypt }) => {
      const task = `decrypt_list_full_with_failures ${name}`;
      return bench(task, benchOptions(task), async () => {
        const result = await decrypt();
        strictEqual(result.successes.length, VAULT_SIZE);
      });
    }),
    runOptions(`decrypt full list, vault size ${VAULT_SIZE}, ${RUNS} runs`, RUNS),
  );
});
