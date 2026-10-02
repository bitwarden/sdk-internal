// Performance harness: master-password unlock through the WASM boundary.
//
//   password ──KDF──► master key ──stretch──► unwrap user key
//
// Times `PureCrypto.decrypt_user_key_with_master_password`, the crypto core of a master-password
// unlock. The KDF dominates; client and state setup are negligible next to it.
//
// Env:
//   PERF_UNLOCK_RUNS  timed runs per KDF                     (default 5)
//   PERF_LABEL        writes perf/results/<label>-unlock.json when set

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { init_sdk, PureCrypto, type Kdf } from "@bitwarden/sdk-internal";

const RUNS = Number(process.env.PERF_UNLOCK_RUNS ?? 5);
const WARMUP_RUNS = 1;
const LABEL = process.env.PERF_LABEL;
const PASSWORD = "correct horse battery staple";
const EMAIL = "perf@bitwarden.com";
const USER_KEY_SIZE = 64;

const RESULTS_DIR = join(dirname(fileURLToPath(import.meta.url)), "results");

// Bitwarden's current defaults for new accounts.
const KDFS: { name: string; kdf: Kdf }[] = [
  { name: "pbkdf2-600k", kdf: { pBKDF2: { iterations: 600_000 } } },
  { name: "argon2id-3-64MiB-4", kdf: { argon2id: { iterations: 3, memory: 64, parallelism: 4 } } },
];

interface Stats {
  kdf: string;
  runsMs: number[];
  medianMs: number;
  minMs: number;
}

const allStats: Stats[] = [];

function report(): void {
  const rows = allStats.map(
    (s) =>
      `${s.kdf.padEnd(20)} median ${s.medianMs.toFixed(1).padStart(8)} ms  min ${s.minMs.toFixed(1).padStart(8)} ms`,
  );
  console.log(`unlock, ${RUNS} runs\n${rows.join("\n")}`);

  if (!LABEL) {
    return;
  }
  mkdirSync(RESULTS_DIR, { recursive: true });
  const file = join(RESULTS_DIR, `${LABEL}-unlock.json`);
  writeFileSync(file, JSON.stringify({ label: LABEL, stats: allStats }, null, 2));
}

describe("unlock performance", () => {
  beforeAll(() => init_sdk());
  afterAll(report);

  it.each(KDFS)("$name", ({ name, kdf }) => {
    const userKey = PureCrypto.make_user_key_aes256_cbc_hmac();
    const wrapped = PureCrypto.encrypt_user_key_with_master_password(userKey, PASSWORD, EMAIL, kdf);

    const unlock = () =>
      PureCrypto.decrypt_user_key_with_master_password(wrapped, PASSWORD, EMAIL, kdf);

    for (let i = 0; i < WARMUP_RUNS; i++) {
      unlock();
    }

    const runsMs: number[] = [];
    for (let i = 0; i < RUNS; i++) {
      const start = performance.now();
      const unlocked = unlock();
      runsMs.push(performance.now() - start);

      // Guards against silently measuring a failing unlock.
      expect(unlocked.length).toBe(USER_KEY_SIZE);
    }

    const sorted = [...runsMs].sort((a, b) => a - b);
    allStats.push({
      kdf: name,
      runsMs,
      medianMs: sorted[Math.floor(sorted.length / 2)],
      minMs: sorted[0],
    });
  });
});
