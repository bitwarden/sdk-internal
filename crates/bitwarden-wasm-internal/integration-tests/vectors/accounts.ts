// Accounts to seed, in the shape the server emulator takes them.
//
// A vector is the account's definition: the ciphertext the server serves, and the plaintext it must
// decrypt to. Tests name a vector and assert on what an operation leaves behind; they do not carry
// key material of their own.

import type { SeedAccount } from "../server-emulator/server-emulator";
import { asEncString, asKeyId } from "../tests/type-assertion-helpers";
import {
  V2_DECRYPTED_USER_KEY,
  V2_KDF_PARAMS,
  V2_PRIVATE_KEY,
  V2_SECURITY_STATE,
  V2_SIGNED_PUBLIC_KEY,
  V2_SIGNING_KEY,
} from "../tests/v2-fixtures";
import {
  MASTER_KEY_WRAPPED_USER_KEY,
  PRIVATE_KEY,
  TEST_EMAIL,
  TEST_KDF_PARAMS,
  TEST_PASSWORD,
  TEST_USER_ID,
} from "../tests/utils";

/** The master-password unlock data {@link MASTER_PASSWORD_ACCOUNT} is defined by. */
export const MASTER_PASSWORD_UNLOCK = {
  masterKeyWrappedUserKey: asEncString(MASTER_KEY_WRAPPED_USER_KEY),
  salt: TEST_EMAIL,
  kdf: TEST_KDF_PARAMS,
};

/** A V1 account that unlocks with a master password. */
export const MASTER_PASSWORD_ACCOUNT: SeedAccount = {
  name: "master-password-account",
  account: {
    userId: String(TEST_USER_ID),
    email: TEST_EMAIL,
    kdf: TEST_KDF_PARAMS,
    securityVersion: 1,
    accountCryptographicState: { V1: { private_key: asEncString(PRIVATE_KEY) } },
  },
  unlockMethods: [
    {
      masterPasswordUnlock: {
        password: TEST_PASSWORD,
        master_password_unlock: MASTER_PASSWORD_UNLOCK,
      },
    },
  ],
  rawCryptographicState: {
    userKey: "",
    masterKey: null,
    privateKey: PRIVATE_KEY,
    publicKey: "cHVibGljLWtleQ==",
  },
};

/** The key id the server has already recorded for {@link V2_ACCOUNT_WITH_RECORDED_KEY_ID}. */
export const RECORDED_KEY_ID = asKeyId("000102030405060708090a0b0c0d0e0f");

/**
 * A V2 account, whose user key carries a key id.
 */
export const V2_ACCOUNT: SeedAccount = {
  name: "v2-account",
  account: {
    userId: String(TEST_USER_ID),
    email: TEST_EMAIL,
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
    privateKey: String(V2_PRIVATE_KEY),
    publicKey: "cHVibGljLWtleQ==",
    verifyingKey: "dmVyaWZ5aW5nLWtleQ==",
  },
};

/** The same account, with a key id the server already recorded — nothing left to backfill. */
export const V2_ACCOUNT_WITH_RECORDED_KEY_ID: SeedAccount = {
  ...V2_ACCOUNT,
  name: "v2-account-with-recorded-key-id",
  account: { ...V2_ACCOUNT.account, userKeyId: RECORDED_KEY_ID },
};
