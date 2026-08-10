// Low-level assertions on the three master-password operations that rewrite the account's key material:
// changing the KDF, rotating the user key, and minting keys at registration.
//
// These read the request bodies and the stored account on purpose. A KDF change is only correct if the
// two halves it posts agree with each other and with what it persists, and that agreement is not visible
// from the outside — an account that unlocks can still have been left with a salt or a KDF variant the
// server and the client disagree about. Expect these to break whenever the wire shape changes; that is
// what they are for.

import {
  unlockMethodFor,
  validateAfterLockUnlock,
  validateAfterLogoutLogin,
} from "../model-server/sync";
import {
  assertRotationHarnessClean,
  expectRotationSucceeds,
  ROTATION_TIMEOUT,
  setupRotation,
  UNLOCK_METHOD,
  type RotationCase,
  type RotationHarness,
} from "../rotation-cases";
import {
  assertRegistrationHarnessClean,
  newClient,
  organization,
  passwordRegistrationRequest,
  REGISTRATION_TIMEOUT,
  setupRegistration,
  type RegistrationHarness,
} from "../registration-support";
import { loadUserVectors, userVector } from "../test-vectors/load";
import {
  CHANGE_KDF_ROUTE,
  CHANGE_KDF_TIMEOUT,
  KDF_TYPE,
  NEW_ARGON2,
  NEW_PBKDF2,
  setupChangeKdf,
  type ChangeKdfHarness,
} from "./change-kdf-support";

const users = loadUserVectors();

describe("change kdf", () => {
  let harness: ChangeKdfHarness;

  afterEach(() => harness.assertClean());

  describe("request", () => {
    it(
      "posts the re-derived authentication and unlock data under the new KDF",
      async () => {
        harness = await setupChangeKdf();
        const { api, client, vector, servers } = harness;
        const before = api.db.user(api.soleUserId()).masterPasswordUnlock!;

        await client.user_crypto_management().change_kdf(vector.account.password, NEW_PBKDF2);

        const posted = servers.bodyFor(CHANGE_KDF_ROUTE);
        expect(Object.keys(posted).sort()).toEqual([
          "authenticationData",
          "masterPasswordHash",
          "unlockData",
        ]);
        expect(Object.keys(posted.authenticationData).sort()).toEqual([
          "kdf",
          "masterPasswordAuthenticationHash",
          "salt",
        ]);
        expect(Object.keys(posted.unlockData).sort()).toEqual([
          "kdf",
          "masterKeyWrappedUserKey",
          "salt",
        ]);

        // Both halves carry the new KDF; memory and parallelism are omitted for PBKDF2.
        const kdf = { kdfType: KDF_TYPE.pbkdf2Sha256, iterations: 700_000 };
        expect(posted.authenticationData.kdf).toEqual(kdf);
        expect(posted.unlockData.kdf).toEqual(kdf);

        // The salt is carried over from the current unlock data, not re-derived.
        expect(posted.authenticationData.salt).toBe(before.salt);
        expect(posted.unlockData.salt).toBe(before.salt);

        // The user key is re-wrapped under the master key derived with the new KDF.
        expect(posted.unlockData.masterKeyWrappedUserKey).toMatch(/^2\./);
        expect(posted.unlockData.masterKeyWrappedUserKey).not.toBe(before.masterKeyWrappedUserKey);
      },
      CHANGE_KDF_TIMEOUT,
    );

    it(
      "proves possession with a hash derived under the old KDF",
      async () => {
        harness = await setupChangeKdf();
        const { client, vector, servers } = harness;

        await client.user_crypto_management().change_kdf(vector.account.password, NEW_PBKDF2);

        const posted = servers.bodyFor(CHANGE_KDF_ROUTE);
        // `masterPasswordHash` is the old-KDF hash the server authenticates the change with;
        // `authenticationData` is what replaces it. Same password, different KDF, so they differ.
        // The model rejects the change outright when the hash is absent, so reaching here at all
        // shows one was sent.
        expect(posted.masterPasswordHash).not.toBe(
          posted.authenticationData.masterPasswordAuthenticationHash,
        );
        expect(posted.masterPasswordHash).not.toBe("");
      },
      CHANGE_KDF_TIMEOUT,
    );

    it(
      "converts the argon2id variant across the boundary",
      async () => {
        harness = await setupChangeKdf();
        const { api, client, local, vector, servers } = harness;

        await client.user_crypto_management().change_kdf(vector.account.password, NEW_ARGON2);

        const posted = servers.bodyFor(CHANGE_KDF_ROUTE);
        const kdf = { kdfType: KDF_TYPE.argon2id, iterations: 3, memory: 16, parallelism: 4 };
        expect(posted.authenticationData.kdf).toEqual(kdf);
        expect(posted.unlockData.kdf).toEqual(kdf);

        // Round trip: the argon2id variant survives out to the state bridge and back into the
        // account the server now holds, so neither side has silently dropped a parameter.
        expect(await local.bridge.get_kdf_config()).toEqual(NEW_ARGON2);
        expect(api.db.user(api.soleUserId()).masterPasswordUnlock!.kdf).toEqual(NEW_ARGON2);
      },
      CHANGE_KDF_TIMEOUT,
    );
  });

  describe("persisted state", () => {
    it(
      "writes the new KDF config and unlock data to the state bridge",
      async () => {
        harness = await setupChangeKdf();
        const { api, client, local, vector, servers } = harness;

        await client.user_crypto_management().change_kdf(vector.account.password, NEW_PBKDF2);

        expect(await local.bridge.get_kdf_config()).toEqual(NEW_PBKDF2);

        const persisted = await local.bridge.get_masterpassword_unlock_data();
        // Exactly what was posted, so client and server cannot disagree about the wrapped key. The
        // bridge holds the SDK's own `Kdf` while the wire carries the server's numeric form, so the
        // KDF is compared after conversion and the rest byte for byte.
        const posted = servers.bodyFor(CHANGE_KDF_ROUTE).unlockData;
        expect(persisted).toEqual({
          masterKeyWrappedUserKey: posted.masterKeyWrappedUserKey,
          salt: posted.salt,
          kdf: NEW_PBKDF2,
        });
        // And the account the server stored agrees with both.
        expect(api.db.user(api.soleUserId()).masterPasswordUnlock).toEqual({
          masterKeyWrappedUserKey: posted.masterKeyWrappedUserKey,
          salt: posted.salt,
          kdf: NEW_PBKDF2,
        });
      },
      CHANGE_KDF_TIMEOUT,
    );

    it(
      "leaves the persisted unlock data usable: a fresh client recovers the same user key",
      async () => {
        harness = await setupChangeKdf();
        const { api, client, local, vector } = harness;

        await client.user_crypto_management().change_kdf(vector.account.password, NEW_PBKDF2);

        // A KDF change re-wraps the user key without changing it, so the vector's recorded key and
        // its whole plaintext vault must still be reachable — from this client's own local state, and
        // from a client that has nothing but what the server holds.
        await validateAfterLockUnlock(local, unlockMethodFor(api, vector.account.email), vector);
        await validateAfterLogoutLogin(api, vector.account.email, vector);
      },
      CHANGE_KDF_TIMEOUT,
    );
  });

  it(
    "never sends the password or the user key",
    async () => {
      harness = await setupChangeKdf();
      const { api, client, vector, servers } = harness;

      await client.user_crypto_management().change_kdf(vector.account.password, NEW_PBKDF2);

      // The account's password, user key, private key and master key are all watched by the server's
      // inspector on every request, so this covers the whole exchange rather than one body.
      expect(servers.requests).not.toEqual([]);
      expect(api.secretLeaks()).toEqual([]);
    },
    CHANGE_KDF_TIMEOUT,
  );
});

const rotationCases: [string, RotationCase][] = [
  [
    "V1 master password",
    {
      vector: userVector(users, "v1-argon2id-password"),
      method: (vector) => ({ Password: { password: vector.account.password } }),
      expectedUnlockMethod: UNLOCK_METHOD.masterPassword,
    },
  ],
  [
    "V1 master password at minimum KDF iterations",
    {
      vector: userVector(users, "v1-pbkdf2-min-iterations"),
      method: (vector) => ({ Password: { password: vector.account.password } }),
      expectedUnlockMethod: UNLOCK_METHOD.masterPassword,
    },
  ],
  [
    "V2 master password",
    {
      vector: userVector(users, "v2-argon2id-blob"),
      method: (vector) => ({ Password: { password: vector.account.password } }),
      expectedUnlockMethod: UNLOCK_METHOD.masterPassword,
    },
  ],
  [
    "the mid-upgrade account",
    {
      vector: userVector(users, "v2-argon2id-upgrade-token"),
      method: (vector) => ({ Password: { password: vector.account.password } }),
      expectedUnlockMethod: UNLOCK_METHOD.masterPassword,
    },
  ],
];

describe("master password key rotation", () => {
  let harness: RotationHarness;

  afterEach(() => assertRotationHarnessClean(harness));

  describe.each(rotationCases)("%s", (_label, rotationCase) => {
    it(
      "posts a V2 cryptographic state, the re-encrypted vault and the right unlock method",
      async () => {
        harness = setupRotation(rotationCase.vector);
        await expectRotationSucceeds(harness, rotationCase);
      },
      ROTATION_TIMEOUT,
    );
  });
});

describe("registering an account that unlocks by master password", () => {
  let harness: RegistrationHarness;

  beforeEach(() => {
    harness = setupRegistration();
  });

  afterEach(() => assertRegistrationHarnessClean(harness));

  it(
    "mints distinct key material for every registration",
    async () => {
      // Two registrations must never collide, which is the one property a seeded or defaulted RNG
      // would silently break.
      const registration = newClient().auth().registration();

      const first = await registration.post_keys_for_user_password_registration(
        passwordRegistrationRequest,
      );
      const second = await registration.post_keys_for_user_password_registration(
        passwordRegistrationRequest,
      );

      expect(first.user_key.toString()).not.toBe(second.user_key.toString());
      expect(JSON.stringify(first.account_cryptographic_state)).not.toBe(
        JSON.stringify(second.account_cryptographic_state),
      );
    },
    REGISTRATION_TIMEOUT,
  );
});

// A sanity check on the fixture the registration suites lean on.
it("has an organization vector to register into", () => {
  expect(organization.publicKey).toBeTruthy();
});
