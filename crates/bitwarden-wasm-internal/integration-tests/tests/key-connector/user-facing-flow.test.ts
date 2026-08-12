// Key connector as a user meets it: migrating an existing master-password account onto it, and
// registering a new account that unlocks by it. Both end the same way — unlock the account again from
// nothing but what the two servers now hold.
//
// `migrate_to_key_connector` is a four-step operation that spans two different servers: it mints a
// random key connector key, wraps the current user key with it, posts the key to the *key connector*,
// then posts the wrapped user key to the *API*. The key connector is a separate model on its own origin,
// so "did the key reach the connector" and "did the account get enrolled at the API" are two independent
// questions about two independent pieces of state.
//
// The migration test does not stop at the stored payloads. It takes the two values the SDK produced —
// the key the connector now stores and the wrapped user key the API now holds — feeds them back in as a
// `keyConnector` unlock method on a fresh client, and asserts that client arrives at the *original* user
// key. Then it unlocks the way a real client does, by URL, so the SDK fetches the key from the connector
// over HTTP rather than being handed a value the test already had.
//
// Registration is the one operation with no second chance: it *chooses* the account's keys, and if it
// emits a state the SDK cannot later load, the account is unrecoverable. Its shared scaffolding lives in
// `tests/registration-support.ts`.

import type { B64, EncString } from "@bitwarden/sdk-internal";

import { LocalState } from "../model-server/local-state";
import { syncToLocalState, unlockMethodFor } from "../model-server/sync";
import { KEY_CONNECTOR_URL } from "../model-server/install";
import {
  assertMigrationHarnessClean,
  KEY_CONNECTOR_KEY_BYTES,
  MIGRATION_CASES,
  MIGRATION_TIMEOUT,
  setupMigration,
  type MigrationHarness,
} from "./migration-support";
import {
  assertRegistrationHarnessClean,
  newClient,
  REGISTRATION_TIMEOUT,
  setupRegistration,
  unlockFreshAndValidate,
  type RegistrationHarness,
} from "../registration-support";
import { unlockVector } from "../test-vectors/unlock";
import { asEncString } from "../type-assertion-helpers";

describe("key connector migration", () => {
  let harness: MigrationHarness;

  afterEach(() => assertMigrationHarnessClean(harness));

  describe.each(MIGRATION_CASES)("%s", (_label, vector) => {
    it(
      "posts the key connector key, enrolls with the wrapped user key, and the pair unlocks the account",
      async () => {
        harness = setupMigration(vector);
        const { api, keyConnector } = harness;
        const local = new LocalState();
        await syncToLocalState(api, vector.account.email, local);
        const client = await local.unlock(unlockMethodFor(api, vector.account.email));
        await client.user_crypto_management().migrate_to_key_connector(KEY_CONNECTOR_URL);

        // The two halves landed in two different places, which is the point of separate models.
        const postedKey = keyConnector.key();
        const wrapped = api.db.user(api.soleUserId()).keyConnectorKeyWrappedUserKey;

        // A freshly minted 32-byte key, not anything derived from the account's existing material.
        if (postedKey === undefined) {
          throw new Error("the key connector stored no key");
        }
        expect(Buffer.from(postedKey, "base64")).toHaveLength(KEY_CONNECTOR_KEY_BYTES);

        // The wrapped user key is an `Aes256CbcHmac` EncString, because the key connector key is
        // stretched into one before wrapping regardless of the user key's own algorithm.
        if (wrapped === undefined) {
          throw new Error("the account was not enrolled in key connector unlock");
        }
        expect(wrapped).toMatch(/^2\./);

        // The new wrapping replaces the master-key one rather than reusing it.
        const previous = vector.unlockMethods.find((m) => "masterPasswordUnlock" in m) as {
          masterPasswordUnlock: { master_password_unlock: { masterKeyWrappedUserKey: unknown } };
        };
        expect(wrapped).not.toBe(
          String(previous.masterPasswordUnlock.master_password_unlock.masterKeyWrappedUserKey),
        );

        // The actual point: the two stored values must unlock the account to the same user key.
        const migrated = await unlockVector(vector, {
          keyConnector: {
            master_key: postedKey as B64,
            user_key: wrapped as EncString,
          },
        });
        expect((await migrated.crypto().get_user_encryption_key()).toString()).toBe(
          vector.rawCryptographicState.userKey,
        );

        // The unlock a real client actually performs after migrating: it is handed the *URL*, not the
        // key, and fetches the key from the connector itself. This is the assertion the separate key
        // connector model exists for — it exercises the connector over HTTP rather than trusting a
        // value the test already had in hand.
        const viaUrl = await local.unlock({
          keyConnectorUrl: {
            url: KEY_CONNECTOR_URL,
            key_connector_key_wrapped_user_key: asEncString(wrapped),
          },
        });
        expect((await viaUrl.crypto().get_user_encryption_key()).toString()).toBe(
          vector.rawCryptographicState.userKey,
        );

        // Proof that the check above has teeth: the same wrapped user key against a *different* key
        // connector key must not unlock anything. Without this, an unlock that ignored `master_key`
        // entirely would satisfy the assertion.
        const wrongKey = Buffer.alloc(KEY_CONNECTOR_KEY_BYTES, 9).toString("base64");
        expect(wrongKey).not.toBe(postedKey);
        await expect(
          unlockVector(vector, {
            keyConnector: { master_key: wrongKey as B64, user_key: wrapped as EncString },
          }),
        ).rejects.toBeDefined();
      },
      MIGRATION_TIMEOUT,
    );
  });
});

describe("registering an account that unlocks by key connector", () => {
  let harness: RegistrationHarness;

  beforeEach(() => {
    harness = setupRegistration();
  });

  afterEach(() => assertRegistrationHarnessClean(harness));

  it(
    "registers a key-connector account, and the account unlocks by key connector",
    async () => {
      const result = await newClient()
        .auth()
        .registration()
        .post_keys_for_key_connector_registration(KEY_CONNECTOR_URL, "sso-identifier");

      // The key must reach the connector, or the account could never be unlocked again.
      expect(harness.keyConnector.key()).toBe(result.key_connector_key.toString());

      await unlockFreshAndValidate(
        result.account_cryptographic_state,
        {
          keyConnector: {
            master_key: result.key_connector_key,
            user_key: result.key_connector_key_wrapped_user_key,
          },
        },
        result.user_key.toString(),
        { pBKDF2: { iterations: 600_000 } },
      );
    },
    REGISTRATION_TIMEOUT,
  );
});
