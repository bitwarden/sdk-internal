// Performance harness: encrypting and decrypting a large vault through the WASM boundary.
//
//   generateVault ──► encrypt_list ──► Cipher[]
//                                        │
//                       ┌────────────────┤
//                       ▼                ▼
//          decrypt_list_with_failures      decrypt_list_full_with_failures
//               (CipherListView)                    (CipherView)
//
// Every arrow is timed; the vault encrypted during setup is the input to both decrypts.
//
// The vault is `PERF_VAULT_SIZE` logins (name, username, password, URI), each with a cipher key.
// Scenarios differ in the account the vault is encrypted for; all ciphers are personal:
//   v1 encryption  V1 account (AES-256-CBC-HMAC user key)
//   v2 encryption  V2 account (XAES-256-GCM user key, COSE)
//
// Env:
//   PERF_VAULT_SIZE  ciphers in the vault                       (default 20000)
//   PERF_RUNS        timed runs per operation                   (default 5)
//   PERF_LABEL       writes perf/results/<label>/<task>.json when set
//
// Run one scenario with vitest's name filter, e.g. `npm run perf -- -t "v2 encryption"`.

import { ok, strictEqual } from "node:assert/strict";

import type {
  Cipher,
  CipherView,
  PasswordManagerClient,
  WasmStateBridge,
} from "@bitwarden/sdk-internal";
import { test } from "vitest";

import { makeOrgInitializedClient, makeStateBridge, makeV2AccountClient } from "../tests/utils";

import { benchOptions, runOptions } from "./bench";
import { generateVault } from "./vault-generator";

const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 20_000);
const RUNS = Number(process.env.PERF_RUNS ?? 5);
const CIPHER_KEY_FLAG = "enableCipherKeyEncryption";

interface Scenario {
  name: string;
  makeClient: (bridge: WasmStateBridge) => Promise<PasswordManagerClient>;
}

const SCENARIOS: Scenario[] = [
  { name: "v2 encryption", makeClient: makeV2AccountClient },
  { name: "v1 encryption", makeClient: makeOrgInitializedClient },
];

/** Encrypts `views` so every cipher has its own cipher key, as clients create today. */
async function encryptVault(client: PasswordManagerClient, views: CipherView[]): Promise<Cipher[]> {
  const encrypted = await client.vault().ciphers().encrypt_list(views);
  return encrypted.map((ctx) => ctx.cipher);
}

test.for(SCENARIOS)("large vault $name", async ({ name, makeClient }, { bench }) => {
  // Client and vault setup is untimed.
  const client = await makeClient(makeStateBridge());
  await client.platform().load_flags(new Map([[CIPHER_KEY_FLAG, true]]));

  const views = generateVault(VAULT_SIZE);
  const vault = await encryptVault(client, views);
  ok(vault.every((cipher) => cipher.key !== undefined));

  const ciphers = client.vault().ciphers();
  const encryptTask = `${name} encrypt_list`;
  const listTask = `${name} decrypt_list_with_failures`;
  const fullTask = `${name} decrypt_list_full_with_failures`;

  // Assertions guard against silently measuring a failing encrypt or decrypt.
  await bench.compare(
    bench(encryptTask, benchOptions(encryptTask), async () => {
      const result = await encryptVault(client, views);
      strictEqual(result.length, VAULT_SIZE);
    }),
    bench(listTask, benchOptions(listTask), async () => {
      const result = await ciphers.decrypt_list_with_failures(vault);
      strictEqual(result.successes.length, VAULT_SIZE);
    }),
    bench(fullTask, benchOptions(fullTask), async () => {
      const result = await ciphers.decrypt_list_full_with_failures(vault);
      strictEqual(result.successes.length, VAULT_SIZE);
    }),
    runOptions(`large vault ${name}, vault size ${VAULT_SIZE}, ${RUNS} runs`, RUNS),
  );
});
