// The three ways a KDF change refuses, kept so none of them starts half-applying.
//
// A partially applied change is the failure that matters: an account whose stored KDF no longer matches
// the unlock data it was derived with cannot be opened by anyone. So each case asserts not just that the
// call rejected but that both sides are exactly as they were, and that the account still unlocks under
// its original password.

import type { Kdf } from "@bitwarden/sdk-internal";
import { ChangeKdfError, isChangeKdfError } from "@bitwarden/sdk-internal";

import { unlockMethodFor, validateAfterLockUnlock } from "../model-server/sync";
import {
  CHANGE_KDF_ROUTE,
  CHANGE_KDF_TIMEOUT,
  NEW_PBKDF2,
  NO_MASTER_PASSWORD_VECTOR,
  setupChangeKdf,
  type ChangeKdfHarness,
} from "./change-kdf-support";

/** Awaits a rejection and narrows it to a {@link ChangeKdfError}. */
async function rejection(promise: Promise<void>): Promise<ChangeKdfError> {
  const thrown = await promise.then(
    () => undefined,
    (error) => error,
  );
  if (!isChangeKdfError(thrown)) {
    throw new Error(`expected a ChangeKdfError, got ${thrown}`);
  }
  return thrown;
}

describe("change kdf", () => {
  let harness: ChangeKdfHarness;

  afterEach(() => harness.assertClean());

  describe("failures", () => {
    it(
      "leaves state untouched when the server rejects the change",
      async () => {
        harness = await setupChangeKdf({
          extraRoutes: {
            [CHANGE_KDF_ROUTE]: () => ({ status: 400, json: { message: "kdf change rejected" } }),
          },
        });
        const { api, client, local, vector } = harness;
        const before = { ...api.db.user(api.soleUserId()).masterPasswordUnlock! };

        const error = await rejection(
          client.user_crypto_management().change_kdf(vector.account.password, NEW_PBKDF2),
        );

        expect(error.variant).toBe("Api");
        // Nothing is persisted on either side, so the account is not left half-migrated.
        expect(await local.bridge.get_kdf_config()).toEqual(vector.account.kdf);
        expect(api.db.user(api.soleUserId()).masterPasswordUnlock).toEqual(before);
        // And it still opens under the original password.
        await validateAfterLockUnlock(local, unlockMethodFor(api, vector.account.email), vector);
      },
      CHANGE_KDF_TIMEOUT,
    );

    it(
      "errors before making a request when the unlock data is missing",
      async () => {
        // A trusted-device account has no master password at all, so there is no unlock data to
        // re-derive and nothing the change could be based on.
        harness = await setupChangeKdf({ vector: NO_MASTER_PASSWORD_VECTOR });
        const { client, servers } = harness;

        const error = await rejection(
          client.user_crypto_management().change_kdf("irrelevant-password", NEW_PBKDF2),
        );

        expect(error.variant).toBe("MissingMasterPasswordUnlockData");
        expect(servers.requests).toEqual([]);
      },
      CHANGE_KDF_TIMEOUT,
    );

    it(
      "errors before making a request when the new KDF is below the allowed minimum",
      async () => {
        harness = await setupChangeKdf();
        const { api, client, local, vector, servers } = harness;
        const before = { ...api.db.user(api.soleUserId()).masterPasswordUnlock! };
        const belowMinimum: Kdf = { argon2id: { iterations: 1, memory: 16, parallelism: 1 } };

        const error = await rejection(
          client.user_crypto_management().change_kdf(vector.account.password, belowMinimum),
        );

        expect(error.variant).toBe("MasterPassword");
        // The floor is enforced before anything is derived or sent.
        expect(servers.requests).toEqual([]);
        expect(await local.bridge.get_kdf_config()).toEqual(vector.account.kdf);
        expect(api.db.user(api.soleUserId()).masterPasswordUnlock).toEqual(before);
      },
      CHANGE_KDF_TIMEOUT,
    );
  });
});
