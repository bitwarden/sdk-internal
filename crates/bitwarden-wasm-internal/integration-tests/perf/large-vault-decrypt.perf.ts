// Performance harness: decrypting a large vault through the WASM boundary.
//
//   generateVault ──► encrypt_list (setup, untimed) ──► Cipher[]
//                                                        │
//                       ┌────────────────────────────────┤
//                       ▼                                ▼
//          decrypt_list_with_failures      decrypt_list_full_with_failures
//               (CipherListView)                    (CipherView)
//
// The vault is `PERF_VAULT_SIZE` logins (name, username, password, URI), each with a cipher key.
// Scenarios differ in the account the vault is encrypted for:
//   v1          V1 account (AES-256-CBC-HMAC user key), 20% organization ciphers
//   v1-personal V1 account, personal ciphers only
//   v2-personal V2 account (XAES-256-GCM user key, COSE), personal ciphers only
//
// Env:
//   PERF_VAULT_SIZE  ciphers in the vault             (default 10000)
//   PERF_RUNS        timed runs per operation         (default 5)
//   PERF_SCENARIOS   comma-separated scenario filter  (default all)
//   PERF_LABEL       writes perf/results/<label>.json when set

import { ok, strictEqual } from "node:assert/strict";

import type {
  Cipher,
  OrganizationId,
  PasswordManagerClient,
  WasmStateBridge,
} from "@bitwarden/sdk-internal";

import { TEST_ORGANIZATION_ID } from "../tests/org-fixtures";
import { makeOrgInitializedClient, makeStateBridge, makeV2AccountClient } from "../tests/utils";

import { makeBench, report, type Stats } from "./bench";
import { generateVault } from "./vault-generator";

const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 10_000);
const RUNS = Number(process.env.PERF_RUNS ?? 5);
const SCENARIO_FILTER = process.env.PERF_SCENARIOS?.split(",");
const CIPHER_KEY_FLAG = "enableCipherKeyEncryption";
const MS_TO_US = 1000;

interface Scenario {
  name: string;
  makeClient: (bridge: WasmStateBridge) => Promise<PasswordManagerClient>;
  orgId: OrganizationId | undefined;
}

const SCENARIOS: Scenario[] = [
  { name: "v1", makeClient: makeOrgInitializedClient, orgId: TEST_ORGANIZATION_ID },
  { name: "v1-personal", makeClient: makeOrgInitializedClient, orgId: undefined },
  { name: "v2-personal", makeClient: makeV2AccountClient, orgId: undefined },
].filter((s) => !SCENARIO_FILTER || SCENARIO_FILTER.includes(s.name));

/** Builds an encrypted vault in which every cipher has its own cipher key, as clients create today. */
async function buildVault(
  client: PasswordManagerClient,
  orgId?: OrganizationId,
): Promise<Cipher[]> {
  await client.platform().load_flags(new Map([[CIPHER_KEY_FLAG, true]]));

  const encrypted = await client.vault().ciphers().encrypt_list(generateVault(VAULT_SIZE, orgId));
  return encrypted.map((ctx) => ctx.cipher);
}

/** E.g. `{ "2.": 10000 }` or `{ "7.": 5000, blob: 5000 }`: which encryption formats the vault holds. */
function formats(vault: Cipher[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const cipher of vault) {
    const format = cipher.data !== undefined ? "blob" : String(cipher.name).slice(0, 2);
    counts[format] = (counts[format] ?? 0) + 1;
  }
  return counts;
}

function usPerCipher(s: Stats): Record<string, string> {
  return { "µs/cipher": ((s.medianMs * MS_TO_US) / VAULT_SIZE).toFixed(1) };
}

export async function run(): Promise<void> {
  const bench = makeBench(`large vault decrypt, vault size ${VAULT_SIZE}, ${RUNS} runs`, RUNS);

  // Client and vault setup is untimed; each scenario adds its two decrypt tasks.
  for (const { name, makeClient, orgId } of SCENARIOS) {
    const client = await makeClient(makeStateBridge());
    const vault = await buildVault(client, orgId);
    ok(vault.every((cipher) => cipher.key !== undefined));
    console.log(`${name} formats ${JSON.stringify(formats(vault))}`);

    const ciphers = client.vault().ciphers();

    // Assertions guard against silently measuring a failing decrypt.
    bench.add(`${name} decrypt_list_with_failures`, async () => {
      const result = await ciphers.decrypt_list_with_failures(vault);
      strictEqual(result.successes.length, VAULT_SIZE);
    });
    bench.add(`${name} decrypt_list_full_with_failures`, async () => {
      const result = await ciphers.decrypt_list_full_with_failures(vault);
      strictEqual(result.successes.length, VAULT_SIZE);
    });
  }

  await bench.run();
  report(bench, "", { vaultSize: VAULT_SIZE }, usPerCipher);
}
