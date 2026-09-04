// Low-level assertions on a KDF change: the wire shape, and the state it leaves behind.
//
// These read the request body on purpose. A KDF change is only correct if the two halves it posts
// agree with each other and with what it persists, and that agreement is not visible from the
// outside — an account that unlocks can still have been left with a salt or a KDF variant the
// server and the client disagree about. Expect these to break whenever the wire shape changes; that
// is what they are for.

import { KdfType, type ChangeKdfRequest } from "../model-server/dto";
import { LocalState } from "../model-server/local-state";
import {
  syncToLocalState,
  unlockMethodFor,
  validateAfterLockUnlock,
  validateAfterLogoutLogin,
} from "../model-server/validate";
import {
  CHANGE_KDF_ROUTE,
  CHANGE_KDF_TIMEOUT,
  expectRecordedUserKeyIsLive,
  NEW_ARGON2,
  NEW_PBKDF2,
  setupChangeKdf,
  type ChangeKdfHarness,
} from "./change-kdf-support";

describe("change kdf", () => {
  let harness: ChangeKdfHarness;

  afterEach(() => harness.assertClean());

  describe("request", () => {
    it(
      "posts the re-derived authentication and unlock data under the new KDF",
      async () => {
        harness = await setupChangeKdf();
        const { api, client, email, servers } = harness;
        const before = api.db.userByEmail(email).masterPasswordUnlock;
        if (before === null) {
          throw new Error("the seeded account has no master password unlock data");
        }

        await client
          .user_crypto_management()
          .change_kdf(harness.account.account.password, NEW_PBKDF2);

        const posted = servers.bodyFor<ChangeKdfRequest>(CHANGE_KDF_ROUTE);
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
          "containedKeyId",
          "kdf",
          "masterKeyWrappedUserKey",
          "salt",
        ]);
        // The unlock data names the key it wraps, so a client cannot later unwrap it into the
        // wrong slot. Only the unlock half carries it; the authentication half has no key.
        expect(posted.unlockData.containedKeyId).toMatch(/^[0-9a-f]{32}$/);

        // Both halves carry the new KDF; memory and parallelism are omitted for PBKDF2.
        const kdf = { kdfType: KdfType.pbkdf2Sha256, iterations: 700_000 };
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
        const { client, servers } = harness;

        await client
          .user_crypto_management()
          .change_kdf(harness.account.account.password, NEW_PBKDF2);

        const posted = servers.bodyFor<ChangeKdfRequest>(CHANGE_KDF_ROUTE);
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
        const { api, client, email, local, servers } = harness;

        await client
          .user_crypto_management()
          .change_kdf(harness.account.account.password, NEW_ARGON2);

        const posted = servers.bodyFor<ChangeKdfRequest>(CHANGE_KDF_ROUTE);
        const kdf = { kdfType: KdfType.argon2id, iterations: 3, memory: 16, parallelism: 4 };
        expect(posted.authenticationData.kdf).toEqual(kdf);
        expect(posted.unlockData.kdf).toEqual(kdf);

        // Round trip: the argon2id variant survives out to the state bridge and back into the
        // account the server now holds, so neither side has silently dropped a parameter.
        expect(await local.bridge.get_kdf_config()).toEqual(NEW_ARGON2);
        expect(api.db.userByEmail(email).masterPasswordUnlock?.kdf).toEqual(NEW_ARGON2);
      },
      CHANGE_KDF_TIMEOUT,
    );
  });

  describe("persisted state", () => {
    it(
      "writes the new KDF config and unlock data to the state bridge",
      async () => {
        harness = await setupChangeKdf();
        const { api, client, email, local, servers } = harness;

        await client
          .user_crypto_management()
          .change_kdf(harness.account.account.password, NEW_PBKDF2);

        expect(await local.bridge.get_kdf_config()).toEqual(NEW_PBKDF2);

        // Exactly what was posted, so client and server cannot disagree about the wrapped key. The
        // bridge holds the SDK's own `Kdf` while the wire carries the server's numeric form, so the
        // KDF is compared after conversion and the rest byte for byte.
        const posted = servers.bodyFor<ChangeKdfRequest>(CHANGE_KDF_ROUTE).unlockData;
        const expected = {
          masterKeyWrappedUserKey: posted.masterKeyWrappedUserKey,
          salt: posted.salt,
          kdf: NEW_PBKDF2,
          containedKeyId: posted.containedKeyId,
        };
        expect(await local.bridge.get_masterpassword_unlock_data()).toEqual(expected);
        // And the account the server stored agrees with both.
        expect(api.db.userByEmail(email).masterPasswordUnlock).toEqual(expected);
      },
      CHANGE_KDF_TIMEOUT,
    );

    it(
      "leaves the account openable from local state and from the server alike",
      async () => {
        harness = await setupChangeKdf();
        const { api, client, email, local, account, expected } = harness;

        await client.user_crypto_management().change_kdf(account.account.password, NEW_PBKDF2);

        // A KDF change re-wraps the user key without changing it, so the account must still open —
        // from this client's own local state, and from a client that has nothing but what the
        // server holds. Lock/unlock runs first: a sync would overwrite the local state it checks.
        await validateAfterLockUnlock(local, account.account.password, expected);
        await validateAfterLogoutLogin(api, email, expected);
      },
      CHANGE_KDF_TIMEOUT,
    );

    it(
      "re-wraps the same user key rather than issuing a new one",
      async () => {
        harness = await setupChangeKdf();
        const { api, client, email, account } = harness;
        await expectRecordedUserKeyIsLive(client);
        const before = await client.crypto().get_user_encryption_key();

        await client.user_crypto_management().change_kdf(account.account.password, NEW_PBKDF2);

        // A fresh client, holding nothing but what the server now serves, derives the same key.
        const reopened = new LocalState();
        await syncToLocalState(api, email, reopened);
        const next = await reopened.unlock(unlockMethodFor(api, email));
        expect(await next.crypto().get_user_encryption_key()).toBe(before);
      },
      CHANGE_KDF_TIMEOUT,
    );
  });

  it(
    "never sends the password or the user key",
    async () => {
      harness = await setupChangeKdf();
      const { api, client, servers, account } = harness;

      await client.user_crypto_management().change_kdf(account.account.password, NEW_PBKDF2);

      // The password, user key and private key are watched by the server's inspector on every
      // request, so this covers the whole exchange rather than one body.
      expect(servers.requests).not.toEqual([]);
      expect(api.secretLeaks()).toEqual([]);
    },
    CHANGE_KDF_TIMEOUT,
  );
});
