// Performance harness: decrypting a large vault in one call vs pulling it through the iterable.
//
//   generateVault ──► encrypt_list ──► Cipher[] ──┬──► decrypt_list_with_failures          one call
//                                                 ├──► decrypt_list_iterable ──► for await  results
//                                                 │      (async source)
//                                                 └──► stream handles, as baselines:
//                                                        decrypt_list_stream        (sync source)
//                                                        decrypt_list_async_stream  (async source)
//
// Every decrypt is timed; the vault encrypted during setup is the input to all of them. Each task
// collects the views into one JS array, as a client listing the vault would. See
// `cipher-stream.ts` for the modes. The `1% failing` tasks run over a copy of the vault where one
// cipher in a hundred fails to decrypt, to show what failures cost.
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
//   PERF_CHUNK_SIZE   ciphers per pull in the chunk tasks        (default 250)
//   PERF_LABEL        writes perf/results/<label>/<task>.json when set
//
// Memory is measured separately, one mode per process, by `iterator-memory.perf.ts`.

import { ok, strictEqual } from "node:assert/strict";

import { test } from "vitest";

import { makeStateBridge, makeV2AccountClient } from "../tests/utils";

import { benchOptions, runOptions } from "./bench";
import { corruptVault, decryptVault, type StreamMode } from "./cipher-stream";
import { generateVault } from "./vault-generator";

const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 12_000);
const RUNS = Number(process.env.PERF_RUNS ?? 5);
const CHUNK_SIZE = Number(process.env.PERF_CHUNK_SIZE ?? 250);
const FAILING_FRACTION = 0.01;
const CIPHER_KEY_FLAG = "enableCipherKeyEncryption";
// Every task takes about half a second and runs `PERF_RUNS` times plus a warmup; together they
// outlast vitest's default 60 s test timeout.
const TIMEOUT = 30 * 60_000;

interface Task {
  name: string;
  mode: StreamMode;
  chunkSize: number;
  failing: boolean;
}

const TASKS: Task[] = [
  { name: "array decrypt_list_with_failures", mode: "array", chunkSize: 0, failing: false },
  { name: "array, 1% failing", mode: "array", chunkSize: 0, failing: true },
  {
    name: `iterable-results ${CHUNK_SIZE}`,
    mode: "iterable-results",
    chunkSize: CHUNK_SIZE,
    failing: false,
  },
  {
    name: `iterable-results ${CHUNK_SIZE}, 1% failing`,
    mode: "iterable-results",
    chunkSize: CHUNK_SIZE,
    failing: true,
  },
  {
    name: `async source next_chunk_async ${CHUNK_SIZE}`,
    mode: "async-source-chunk",
    chunkSize: CHUNK_SIZE,
    failing: false,
  },
  {
    name: "async source next_item_async",
    mode: "async-source-item",
    chunkSize: 1,
    failing: false,
  },
  { name: `sync next_chunk ${CHUNK_SIZE}`, mode: "chunk", chunkSize: CHUNK_SIZE, failing: false },
  { name: "sync next_item", mode: "item", chunkSize: 1, failing: false },
];

test(
  "iterator decrypt",
  async ({ bench }) => {
    // Client and vault setup is untimed.
    const client = await makeV2AccountClient(makeStateBridge());
    await client.platform().load_flags(new Map([[CIPHER_KEY_FLAG, true]]));

    const encrypted = await client.vault().ciphers().encrypt_list(generateVault(VAULT_SIZE));
    const vault = encrypted.map((ctx) => ctx.cipher);
    ok(vault.every((cipher) => cipher.key !== undefined));

    const [failingVault, failing] = corruptVault(vault, FAILING_FRACTION);
    ok(failing > 0);

    const ciphers = client.vault().ciphers();

    // Assertions guard against silently measuring a decrypt that fails or stops early.
    await bench.compare(
      ...TASKS.map((task) =>
        bench(task.name, benchOptions(`iterator ${task.name}`), async () => {
          const input = task.failing ? failingVault : vault;
          const { views, failures } = await decryptVault(ciphers, input, task.mode, task.chunkSize);
          const expectedFailures = task.failing ? failing : 0;
          strictEqual(failures, expectedFailures);
          strictEqual(views.length, VAULT_SIZE - expectedFailures);
        }),
      ),
      runOptions(`iterator decrypt, vault size ${VAULT_SIZE}, ${RUNS} runs`, RUNS),
    );
  },
  TIMEOUT,
);
