// Performance harness: master-password unlock through the WASM boundary.
//
//   password ──KDF──► master key ──stretch──► unwrap user key
//
// Times `PureCrypto.decrypt_user_key_with_master_password`, the crypto core of a master-password
// unlock. The KDF dominates; client and state setup are negligible next to it.
//
// Env:
//   PERF_UNLOCK_RUNS  timed runs per KDF                              (default 5)
//   PERF_LABEL        writes perf/results/<label>/unlock-<kdf>.json when set

import { strictEqual } from "node:assert/strict";

import { init_sdk, PureCrypto, type Kdf } from "@bitwarden/sdk-internal";
import { beforeAll, test } from "vitest";

import { benchOptions, runOptions } from "./bench";

const RUNS = Number(process.env.PERF_UNLOCK_RUNS ?? 5);
const PASSWORD = "correct horse battery staple";
const EMAIL = "perf@bitwarden.com";
const USER_KEY_SIZE = 64;

// Bitwarden's current defaults for new accounts, then high-cost settings.
const KDFS: { name: string; kdf: Kdf }[] = [
  { name: "pbkdf2-600k", kdf: { pBKDF2: { iterations: 600_000 } } },
  { name: "argon2id-3-64MiB-4", kdf: { argon2id: { iterations: 3, memory: 64, parallelism: 4 } } },
  { name: "pbkdf2-2m", kdf: { pBKDF2: { iterations: 2_000_000 } } },
  {
    name: "argon2id-3-1024MiB-4",
    kdf: { argon2id: { iterations: 3, memory: 1024, parallelism: 4 } },
  },
];

beforeAll(() => init_sdk());

test.for(KDFS)("unlock $name", async ({ name, kdf }, { bench }) => {
  const userKey = PureCrypto.make_user_key_aes256_cbc_hmac();
  const wrapped = PureCrypto.encrypt_user_key_with_master_password(userKey, PASSWORD, EMAIL, kdf);

  // The assertion guards against silently measuring a failing unlock.
  await bench(name, benchOptions(`unlock-${name}`), () => {
    const unlocked = PureCrypto.decrypt_user_key_with_master_password(
      wrapped,
      PASSWORD,
      EMAIL,
      kdf,
    );
    strictEqual(unlocked.length, USER_KEY_SIZE);
  }).run(runOptions(`unlock ${name}, ${RUNS} runs`, RUNS));
});
