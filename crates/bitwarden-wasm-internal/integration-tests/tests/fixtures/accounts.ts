// Accounts for seeding the model server, in the shape a committed test vector records.
//
// The key material is the same the rest of the suite uses (`utils.ts`, `v2-fixtures.ts`), assembled
// into whole accounts rather than loose constants. The shape is `SeedAccount`, so replacing these
// with vectors loaded from JSON is a change of source and nothing else.

import type { SeedAccount } from "../model-server/api-server";
import { asEncString } from "../type-assertion-helpers";
import {
  MASTER_KEY_WRAPPED_USER_KEY,
  PRIVATE_KEY,
  TEST_EMAIL,
  TEST_KDF_PARAMS,
  TEST_PASSWORD,
  TEST_USER_ID,
} from "../utils";
import {
  V2_DECRYPTED_USER_KEY,
  V2_KDF_PARAMS,
  V2_PRIVATE_KEY,
  V2_SECURITY_STATE,
  V2_SIGNED_PUBLIC_KEY,
  V2_SIGNING_KEY,
} from "../v2-fixtures";

/**
 * The user key `PASSWORD_ACCOUNT` unwraps to.
 *
 * Recorded so the server can watch for it on the wire. Derived from the account's own fixtures — if
 * they change, this goes stale and the leak check silently stops covering the user key, so it is
 * asserted against a live unwrap in `change-kdf-support.ts`.
 */
export const PASSWORD_ACCOUNT_USER_KEY =
  "w2LO+nwV4oxwswVYCxlOfRUseXfvU03VzvKQHrqeklPgiMZrspUe6sOBToCnDn9Ay0tuCBn8ykVVRb7PWhub2Q==";

/** The public key of the RSA key pair `PRIVATE_KEY` wraps. Only the server serves it. */
const PASSWORD_ACCOUNT_PUBLIC_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";

/** A V1 account that unlocks with a master password. The subject of most KDF-change cases. */
export const PASSWORD_ACCOUNT: SeedAccount = {
  name: "v1-pbkdf2-password",
  account: {
    userId: String(TEST_USER_ID),
    email: TEST_EMAIL,
    password: TEST_PASSWORD,
    kdf: TEST_KDF_PARAMS,
    securityVersion: 1,
    accountCryptographicState: { V1: { private_key: asEncString(PRIVATE_KEY) } },
  },
  unlockMethods: [
    {
      masterPasswordUnlock: {
        password: TEST_PASSWORD,
        master_password_unlock: {
          masterKeyWrappedUserKey: asEncString(MASTER_KEY_WRAPPED_USER_KEY),
          salt: TEST_EMAIL,
          kdf: TEST_KDF_PARAMS,
        },
      },
    },
  ],
  rawCryptographicState: {
    userKey: PASSWORD_ACCOUNT_USER_KEY,
    // The master key is not recorded, so it is not watched for. The user key is the value that
    // actually must not escape; the master key never leaves the SDK on this path either way.
    masterKey: null,
    privateKey: PRIVATE_KEY,
    publicKey: PASSWORD_ACCOUNT_PUBLIC_KEY,
  },
};

/**
 * A V2 account with no master password at all.
 *
 * There is no unlock data to re-derive, which is the state a trusted-device or key-connector account
 * is in, and the one a KDF change has to refuse rather than half-apply.
 */
export const NO_MASTER_PASSWORD_ACCOUNT: SeedAccount = {
  name: "v2-argon2id-no-master-password",
  account: {
    userId: "bc010300-0000-4000-8000-000000000000",
    email: "no-master-password@test.bitwarden.com",
    password: "",
    kdf: V2_KDF_PARAMS,
    securityVersion: 2,
    accountCryptographicState: {
      V2: {
        private_key: V2_PRIVATE_KEY,
        signing_key: V2_SIGNING_KEY,
        security_state: V2_SECURITY_STATE,
        signed_public_key: V2_SIGNED_PUBLIC_KEY,
      },
    },
  },
  unlockMethods: [{ decryptedKey: { decrypted_user_key: V2_DECRYPTED_USER_KEY } }],
  rawCryptographicState: {
    userKey: V2_DECRYPTED_USER_KEY,
    masterKey: null,
    privateKey: V2_PRIVATE_KEY,
    publicKey: PASSWORD_ACCOUNT_PUBLIC_KEY,
    verifyingKey: "verifying-key-not-served-in-these-tests",
  },
};
