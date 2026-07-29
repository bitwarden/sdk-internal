// The key-management slice of a sync response, plus the one route the handler calls.

import { KeyId, KmSyncData } from "@bitwarden/sdk-internal";

import { Routes } from "../http-mock";
import { MASTER_KEY_WRAPPED_USER_KEY, TEST_EMAIL, encstring } from "../utils";
import {
  V2_KDF_PARAMS,
  V2_PRIVATE_KEY,
  V2_SECURITY_STATE,
  V2_SIGNED_PUBLIC_KEY,
  V2_SIGNING_KEY,
  V2_USER_KEY_ID,
} from "../v2-fixtures";

/** Route keys, so tests assert against the same strings the mock matches on. */
export const ROUTES = {
  postUserKeyId: "POST /accounts/key-management/user-key-id",
} as const;

/**
 * A full sync payload, as a client hands it to `on_sync` after a sync
 *
 * Individual cases clone and override, e.g. `{ ...SYNC_VECTOR, userDecryption: { ... } }`.
 */
export const SYNC_VECTOR: KmSyncData = {
  userDecryption: {
    userKeyId: V2_USER_KEY_ID as unknown as KeyId,
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

/**
 * {@link SYNC_VECTOR} with the key id absent — an account the server has no key id recorded for,
 * which is what triggers the backfill.
 */
export function withoutUserKeyId(): KmSyncData {
  const { userKeyId: _dropped, ...rest } = SYNC_VECTOR.userDecryption!;
  return { ...SYNC_VECTOR, userDecryption: rest };
}

/** Accepts the key-id backfill. Spread it and override to make the server reject instead. */
export function kmSyncRoutes(): Routes {
  return { [ROUTES.postUserKeyId]: () => ({}) };
}
