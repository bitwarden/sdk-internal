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

import { strictEqual } from "node:assert/strict";

import { init_sdk, PureCrypto, type Kdf } from "@bitwarden/sdk-internal";

import { makeBench, report } from "./bench";

const RUNS = Number(process.env.PERF_UNLOCK_RUNS ?? 5);
const PASSWORD = "correct horse battery staple";
const EMAIL = "perf@bitwarden.com";
const USER_KEY_SIZE = 64;
const RESULTS_SUFFIX = "-unlock";

// Bitwarden's current defaults for new accounts.
const KDFS: { name: string; kdf: Kdf }[] = [
  { name: "pbkdf2-600k", kdf: { pBKDF2: { iterations: 600_000 } } },
  { name: "argon2id-3-64MiB-4", kdf: { argon2id: { iterations: 3, memory: 64, parallelism: 4 } } },
];

export async function run(): Promise<void> {
  init_sdk();
  const bench = makeBench(`unlock, ${RUNS} runs`, RUNS);

  for (const { name, kdf } of KDFS) {
    const userKey = PureCrypto.make_user_key_aes256_cbc_hmac();
    const wrapped = PureCrypto.encrypt_user_key_with_master_password(userKey, PASSWORD, EMAIL, kdf);

    // The assertion guards against silently measuring a failing unlock.
    bench.add(name, () => {
      const unlocked = PureCrypto.decrypt_user_key_with_master_password(
        wrapped,
        PASSWORD,
        EMAIL,
        kdf,
      );
      strictEqual(unlocked.length, USER_KEY_SIZE);
    });
  }

  await bench.run();
  report(bench, RESULTS_SUFFIX);
}
