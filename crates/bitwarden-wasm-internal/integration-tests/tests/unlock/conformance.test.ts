// The unlock step itself, and the shape of the matrix that exercises it.
//
// `happy-path.test.ts` unlocks through every method on its way to decrypting a vault, so this file
// deliberately does not repeat that. What it covers instead is what a decryption pass can only assert
// indirectly:
//
//   - that the matrix of methods is complete, so a regenerated vector set that silently drops a method
//     (say `authRequest`, which only one account carries) fails here rather than quietly losing coverage;
//   - that every method for one account is *interchangeable* — all of them must land on identical key
//     material, since they are different wrappings of the same user key. A method that unlocked to a
//     subtly wrong key would still decrypt nothing, so this is the assertion that pins it down;
//   - the two invariants the vector set encodes about how vaults are encrypted, asserted from the
//     TypeScript side so a regenerated set that drops one fails here too;
//   - that `initialize_user_crypto` accepts each of the state-backed methods.
//
// Being an inventory of the committed data, this is expected to change whenever the vector set does.

import { unlockMethodName, type UserVector } from "../test-vectors/load";
import { unlockVector } from "../test-vectors/unlock";
import { validateKeys } from "../test-vectors/validate";
import {
  initializeCryptoDefault,
  initializeUserCrypto,
  makePasswordManagerClient,
  makeStateBridge,
  MASTER_KEY_WRAPPED_USER_KEY,
  TEST_EMAIL,
  TEST_KDF_PARAMS,
  TEST_PASSWORD,
  TEST_PIN,
} from "../utils";
import { allPairs, UNLOCK_TIMEOUT, vectors } from "./unlock-support";

/**
 * Every unlock method the vector set is meant to exercise.
 *
 * Hard-coded rather than derived from the vectors, because deriving it from the thing under test would
 * make the completeness check vacuous.
 */
const EXPECTED_METHODS = [
  "authRequest",
  "decryptedKey",
  "deviceKey",
  "keyConnector",
  "masterPasswordUnlock",
  "pinEnvelope",
] as const;

const encstring = (s: string) => s as unknown as never;

describe("unlock methods", () => {
  it("covers every unlock method the vector set is meant to exercise", () => {
    const covered = new Set(allPairs.map(([, methodName]) => methodName));
    expect([...covered].sort()).toEqual([...EXPECTED_METHODS]);
  });

  it("declares each method as a single-variant tagged union", () => {
    // `InitUserCryptoMethod` is an externally tagged enum, so anything other than exactly one key
    // means the vector was written against a different shape than the bindings expose.
    for (const vector of vectors) {
      expect(vector.unlockMethods.length).toBeGreaterThan(0);
      for (const method of vector.unlockMethods) {
        expect(Object.keys(method)).toHaveLength(1);
      }
    }
  });

  it("records which vector covers which method", () => {
    // Not an assertion so much as a readable inventory: if the matrix shifts, the diff here says how.
    const byMethod = new Map<string, string[]>();
    for (const [name, methodName] of allPairs) {
      byMethod.set(methodName, [...(byMethod.get(methodName) ?? []), name]);
    }

    expect(Object.fromEntries([...byMethod].sort(([a], [b]) => a.localeCompare(b)))).toEqual({
      authRequest: ["v1-argon2id-tde"],
      decryptedKey: ["v1-argon2id-password", "v2-pbkdf2-blob"],
      deviceKey: ["v1-argon2id-tde", "v2-argon2id-tde"],
      keyConnector: ["v1-pbkdf2-key-connector", "v2-pbkdf2-key-connector"],
      masterPasswordUnlock: [
        "v1-argon2id-password",
        "v1-pbkdf2-min-iterations",
        "v1-pbkdf2-password",
        "v2-argon2id-blob",
        "v2-argon2id-upgrade-token",
        "v2-pbkdf2-blob",
      ],
      pinEnvelope: ["v1-pbkdf2-password", "v2-argon2id-blob", "v2-argon2id-upgrade-token"],
    });
  });

  it.each(
    allPairs.map(
      ([name, methodName, vector, method]) =>
        [`${name} via ${methodName}`, vector, method] as const,
    ),
  )(
    "unlocks %s to the recorded key material",
    async (_label, vector, method) => {
      const client = await unlockVector(vector, method);
      await validateKeys(client, vector);
    },
    UNLOCK_TIMEOUT,
  );

  // The two invariants the matrix encodes, asserted from the TypeScript side so a regenerated set that
  // silently drops one of them fails here too.
  it("keeps V2 vaults uniformly blob-encrypted and V1 vaults legacy", () => {
    for (const vector of vectors) {
      const isV2 = vector.account.securityVersion >= 2;
      for (const cipher of vector.vault.ciphers) {
        expect(cipher.blobEncrypted).toBe(isV2);
        if (isV2) {
          expect(cipher.keys.cipherKey).not.toBeNull();
        }
      }
    }
  });

  it("covers all three attachment layouts, and only on accounts that can hold them", () => {
    const seen = new Set<string>();
    for (const vector of vectors) {
      const isV2 = vector.account.securityVersion >= 2;
      for (const cipher of vector.vault.ciphers) {
        for (const attachment of Object.values(cipher.keys.attachments)) {
          seen.add(attachment.version);
          if (isV2) {
            // `check_for_old_attachments` rejects a keyless attachment during rotation, so a V2
            // account cannot legitimately hold a pre-v2 one.
            expect(attachment.version).toBe("V2");
          }
        }
      }
    }
    expect([...seen].sort()).toEqual(["V0", "V1", "V2"]);
  });
});

describe("interchangeability of unlock methods", () => {
  const multiMethod = vectors.filter((vector: UserVector) => vector.unlockMethods.length > 1);

  it("has accounts carrying more than one method, so the checks below are not vacuous", () => {
    expect(multiMethod.length).toBeGreaterThan(1);
  });

  it.each(multiMethod.map((vector: UserVector) => [vector.name, vector] as const))(
    "%s reaches the same user key through every one of its methods",
    async (_name, vector) => {
      const keys = new Map<string, string>();
      for (const method of vector.unlockMethods) {
        const client = await unlockVector(vector, method);
        keys.set(
          unlockMethodName(method),
          (await client.crypto().get_user_encryption_key()).toString(),
        );
      }

      // Compared as a map so a failure names the method that diverged rather than just "not equal".
      expect(Object.fromEntries(keys)).toEqual(
        Object.fromEntries(
          [...keys.keys()].map((name) => [name, vector.rawCryptographicState.userKey]),
        ),
      );
      expect(keys.size).toBe(vector.unlockMethods.length);
    },
    UNLOCK_TIMEOUT,
  );
});

describe("user crypto initialization tests", () => {
  it("initializes the user account via master password", async () => {
    const stateBridge = makeStateBridge();
    const client = makePasswordManagerClient(stateBridge);

    initializeUserCrypto(client, {
      masterPasswordUnlock: {
        password: TEST_PASSWORD,
        master_password_unlock: {
          masterKeyWrappedUserKey: encstring(MASTER_KEY_WRAPPED_USER_KEY),
          salt: TEST_EMAIL,
          kdf: TEST_KDF_PARAMS,
        },
      },
    });

    expect(await client.crypto().get_user_encryption_key()).toBeDefined();
  });

  it("initializes the user account via PIN Envelope", async () => {
    // Set up a PIN with BeforeFirstUnlock so the persistent envelope is written to the bridge.
    const stateBridge = makeStateBridge();
    const setupClient = makePasswordManagerClient(stateBridge);
    await initializeCryptoDefault(setupClient);

    await setupClient
      .user_crypto_management()
      .pin_settings()
      .set_pin(TEST_PIN, "BeforeFirstUnlock");

    const pinEnvelope = await stateBridge.get_persistent_pin_envelope();
    expect(pinEnvelope).toBeDefined();

    // Now make a new client and initialize with the PIN envelope.
    const client = makePasswordManagerClient(stateBridge);
    await initializeUserCrypto(client, {
      pinEnvelope: { pin: TEST_PIN, pin_protected_user_key_envelope: pinEnvelope! },
    });

    expect(await client.crypto().get_user_encryption_key()).toBeDefined();
  });

  it("initializes the user account via PIN State", async () => {
    // Set up a PIN with BeforeFirstUnlock so the persistent envelope is written to the bridge.
    const stateBridge = makeStateBridge();
    const setupClient = makePasswordManagerClient(stateBridge);
    initializeCryptoDefault(setupClient);

    await setupClient
      .user_crypto_management()
      .pin_settings()
      .set_pin(TEST_PIN, "BeforeFirstUnlock");

    const pinState = await stateBridge.get_encrypted_pin();
    expect(pinState).toBeDefined();

    // Now make a new client and initialize with the PIN state.
    const client = makePasswordManagerClient(stateBridge);
    await initializeUserCrypto(client, { pinState: { pin: TEST_PIN } });

    expect(await client.crypto().get_user_encryption_key()).toBeDefined();
  });
});
