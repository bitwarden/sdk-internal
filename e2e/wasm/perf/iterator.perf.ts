// Performance harness: listing a large vault from state in one call vs through the iterable.
//
//   generateVault ──► encrypt_list ──► Cipher[] ──┬──► decrypt_list_with_failures(vault)   one call
//                                                 │
//                                                 └──► client-managed repository ──┬──► list()
//                                                                                  └──► list_iterable()
//
// Every decrypt is timed; the vault encrypted during setup is the input to all of them. Each task
// collects the views into one JS array, as a client listing the vault would. See
// `cipher-stream.ts` for the modes.
//
// The array task runs first, so later tasks find WASM memory already grown and none of them pays
// for growing it in the timed runs.
//
// The vault is `PERF_VAULT_SIZE` logins (name, username, password, URI), each with a cipher key,
// encrypted for a V2 account (XAES-256-GCM user key, COSE).
//
// Env:
//   PERF_VAULT_SIZE   ciphers in the vault                       (default 12000)
//   PERF_RUNS         timed runs per operation                   (default 5)
//   PERF_CHUNK_SIZE   ciphers per chunk of the iterable          (default 250)
//   PERF_LABEL        writes perf/results/<label>/<task>.json when set
//
// Memory is measured separately, one mode per process, by `iterator-memory.perf.ts`.

import { strictEqual } from "node:assert/strict";

import { test } from "vitest";

import { benchOptions, runOptions } from "./bench";
import { decryptVault, registerVault, type StreamMode } from "./cipher-stream";
import { encryptedVault } from "./decrypt-list-setup";

const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 12_000);
const RUNS = Number(process.env.PERF_RUNS ?? 5);
const CHUNK_SIZE = Number(process.env.PERF_CHUNK_SIZE ?? 250);
// Every task takes about half a second and runs `PERF_RUNS` times plus a warmup; together they
// outlast vitest's default 60 s test timeout.
const TIMEOUT = 30 * 60_000;

const TASKS: { name: string; mode: StreamMode }[] = [
  { name: "array decrypt_list_with_failures", mode: "array" },
  { name: "list", mode: "list" },
  { name: `list_iterable ${CHUNK_SIZE}`, mode: "list-iterable" },
];

test(
  "iterator decrypt",
  async ({ bench }) => {
    // Client and vault setup is untimed.
    const { client, ciphers, vault } = await encryptedVault(VAULT_SIZE, VAULT_SIZE);
    await registerVault(client, vault);

    // Assertions guard against silently measuring a decrypt that fails or stops early.
    await bench.compare(
      ...TASKS.map((task) =>
        bench(task.name, benchOptions(`iterator ${task.name}`), async () => {
          const { views, failures } = await decryptVault(ciphers, vault, task.mode, CHUNK_SIZE);
          strictEqual(failures, 0);
          strictEqual(views.length, VAULT_SIZE);
        }),
      ),
      runOptions(`iterator decrypt, vault size ${VAULT_SIZE}, ${RUNS} runs`, RUNS),
    );
  },
  TIMEOUT,
);
