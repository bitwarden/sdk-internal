// The key-management slice of a sync response, plus the one route the handler calls.

import { Kdf, CryptoSyncData, KeyId, UnsignedSharedKey } from "@bitwarden/sdk-internal";

import { MASTER_KEY_WRAPPED_USER_KEY, TEST_EMAIL, encstring } from "../utils";
import {
  V2_KDF_PARAMS,
  V2_PRIVATE_KEY,
  V2_SECURITY_STATE,
  V2_SIGNED_PUBLIC_KEY,
  V2_SIGNING_KEY,
} from "../v2-fixtures";

const unsignedSharedKey = (s: string) => s as unknown as UnsignedSharedKey;
const keyId = (s: string) => s as unknown as KeyId;

/** The key id the server reports for the account {@link SYNC_VECTOR} describes. */
export const SYNC_VECTOR_USER_KEY_ID = keyId("000102030405060708090a0b0c0d0e0f");

/** A PRF-key-wrapped private key, and the user key encapsulated to the matching public key. */
const PRF_ENCRYPTED_PRIVATE_KEY =
  "2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|cWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=";
const PRF_ENCRYPTED_USER_KEY =
  "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==";

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
    // Stored and read back opaquely, like the upgrade token — the handler never unwraps these, so
    // shape-valid values suffice.
    webAuthnPrfOptions: [
      {
        encryptedPrivateKey: encstring(PRF_ENCRYPTED_PRIVATE_KEY),
        encryptedUserKey: unsignedSharedKey(PRF_ENCRYPTED_USER_KEY),
        credentialId: "test-credential-id",
        transports: ["internal", "hybrid"],
      },
    ],
    userKeyId: SYNC_VECTOR_USER_KEY_ID,
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
