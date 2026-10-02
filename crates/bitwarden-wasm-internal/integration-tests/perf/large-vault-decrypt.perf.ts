// Performance harness: decrypting a large vault through the WASM boundary.
//
//   generateVault ──► encrypt_list (setup, untimed) ──► Cipher[]
//                                                        │
//                       ┌────────────────────────────────┤
//                       ▼                                ▼
//          decrypt_list_with_failures      decrypt_list_full_with_failures
//               (CipherListView)                    (CipherView)
//
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

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import type {
  Cipher,
  OrganizationId,
  PasswordManagerClient,
  WasmStateBridge,
} from "@bitwarden/sdk-internal";

import { TEST_ORGANIZATION_ID } from "../tests/org-fixtures";
import { makeOrgInitializedClient, makeStateBridge, makeV2AccountClient } from "../tests/utils";

import { generateVault } from "./vault-generator";

const VAULT_SIZE = Number(process.env.PERF_VAULT_SIZE ?? 10_000);
const RUNS = Number(process.env.PERF_RUNS ?? 5);
const WARMUP_RUNS = 1;
const LABEL = process.env.PERF_LABEL;
const SCENARIO_FILTER = process.env.PERF_SCENARIOS?.split(",");
const CIPHER_KEY_FLAG = "enableCipherKeyEncryption";
const MS_TO_US = 1000;

const RESULTS_DIR = join(dirname(fileURLToPath(import.meta.url)), "results");

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

interface Stats {
  scenario: string;
  operation: string;
  runsMs: number[];
  medianMs: number;
  minMs: number;
  usPerCipher: number;
}

const allStats: Stats[] = [];

/** Builds an encrypted vault: half legacy (user/org key), half with per-cipher keys. */
async function buildVault(
  client: PasswordManagerClient,
  orgId?: OrganizationId,
): Promise<Cipher[]> {
  const views = generateVault(VAULT_SIZE, orgId);
  const half = Math.floor(views.length / 2);
  const ciphers = client.vault().ciphers();

  const legacy = await ciphers.encrypt_list(views.slice(0, half));

  await client.platform().load_flags(new Map([[CIPHER_KEY_FLAG, true]]));
  const keyed = await ciphers.encrypt_list(views.slice(half));
  await client.platform().load_flags(new Map([[CIPHER_KEY_FLAG, false]]));

  return [...legacy, ...keyed].map((ctx) => ctx.cipher);
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

async function measure(
  scenario: string,
  operation: string,
  run: () => Promise<number>,
): Promise<Stats> {
  for (let i = 0; i < WARMUP_RUNS; i++) {
    await run();
  }

  const runsMs: number[] = [];
  for (let i = 0; i < RUNS; i++) {
    const start = performance.now();
    const decrypted = await run();
    runsMs.push(performance.now() - start);

    // Guards against silently measuring a failing decrypt.
    expect(decrypted).toBe(VAULT_SIZE);
  }

  const sorted = [...runsMs].sort((a, b) => a - b);
  const medianMs = sorted[Math.floor(sorted.length / 2)];
  return {
    scenario,
    operation,
    runsMs,
    medianMs,
    minMs: sorted[0],
    usPerCipher: (medianMs * MS_TO_US) / VAULT_SIZE,
  };
}

function report(stats: Stats[]): void {
  const rows = stats.map(
    (s) =>
      `${s.scenario.padEnd(12)} ${s.operation.padEnd(32)} median ${s.medianMs.toFixed(1).padStart(8)} ms` +
      `  min ${s.minMs.toFixed(1).padStart(8)} ms  ${s.usPerCipher.toFixed(1).padStart(6)} µs/cipher`,
  );
  console.log(`vault size ${VAULT_SIZE}, ${RUNS} runs\n${rows.join("\n")}`);

  if (!LABEL) {
    return;
  }
  mkdirSync(RESULTS_DIR, { recursive: true });
  const file = join(RESULTS_DIR, `${LABEL}.json`);
  writeFileSync(file, JSON.stringify({ label: LABEL, vaultSize: VAULT_SIZE, stats }, null, 2));
}

describe("large vault decrypt performance", () => {
  afterAll(() => report(allStats));

  it.each(SCENARIOS)("$name: list and full decryption", async ({ name, makeClient, orgId }) => {
    const client = await makeClient(makeStateBridge());
    const vault = await buildVault(client, orgId);
    console.log(`${name} formats ${JSON.stringify(formats(vault))}`);

    const ciphers = client.vault().ciphers();

    allStats.push(
      await measure(name, "decrypt_list_with_failures", async () => {
        const result = await ciphers.decrypt_list_with_failures(vault);
        return result.successes.length;
      }),
    );
    allStats.push(
      await measure(name, "decrypt_list_full_with_failures", async () => {
        const result = await ciphers.decrypt_list_full_with_failures(vault);
        return result.successes.length;
      }),
    );
  });
});
