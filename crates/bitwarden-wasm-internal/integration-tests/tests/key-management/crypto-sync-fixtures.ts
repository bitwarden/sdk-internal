// The key-management slice of a sync response, plus the one route the handler calls.

import { Kdf, CryptoSyncData } from "@bitwarden/sdk-internal";

import { MASTER_KEY_WRAPPED_USER_KEY, TEST_EMAIL, encstring } from "../utils";
import {
  V2_KDF_PARAMS,
  V2_PRIVATE_KEY,
  V2_SECURITY_STATE,
  V2_SIGNED_PUBLIC_KEY,
  V2_SIGNING_KEY,
} from "../v2-fixtures";

/**
 * A full sync payload, as a client hands it to `on_sync` after a sync
 *
 * Individual cases clone and override, e.g. `{ ...SYNC_VECTOR, userDecryption: { ... } }`.
 */
export const SYNC_VECTOR: CryptoSyncData = {
  userDecryption: {
    masterPasswordUnlock: {
      kdf: V2_KDF_PARAMS,
      masterKeyWrappedUserKey: encstring(MASTER_KEY_WRAPPED_USER_KEY),
      salt: TEST_EMAIL,
    },
    // The handler stores and reads this back opaquely — it never unwraps it — so shape-valid
    // EncStrings of the two expected variants are enough: Cose_Encrypt0_B64 ("7.") wrapping the V1
    // key under the V2 key, and Aes256Cbc_HmacSha256_B64 ("2.") the other way round.
    v2UpgradeToken: {
      wrapped_user_key_1: V2_PRIVATE_KEY,
      wrapped_user_key_2: encstring(MASTER_KEY_WRAPPED_USER_KEY),
    },
  },
  accountCryptographicState: {
    V2: {
      private_key: V2_PRIVATE_KEY,
      signing_key: V2_SIGNING_KEY,
      security_state: V2_SECURITY_STATE,
      signed_public_key: V2_SIGNED_PUBLIC_KEY,
    },
  },
};

/** Kdf settings that differ from the ones {@link SYNC_VECTOR} carries, for re-sync cases. */
export const CHANGED_KDF_PARAMS: Kdf = {
  argon2id: { iterations: 8, memory: 64, parallelism: 4 },
};
