// The four ways a key connector migration can go sideways, kept so none of them regresses.
//
// Ordering matters more here than in most operations. If the account were enrolled server-side while the
// key connector had not stored the key, the user would be permanently locked out — so a failure at the
// connector must abort before enrollment. The reverse order is the safe one, and the last test documents
// that the SDK does leave an orphaned key behind rather than risk the other way round.
//
// The connector model enforces the real verb constraint (`POST` with a key present is a 409, `PUT` with
// none a 404), so the first test only has to check that the migration completed at all.

import { LocalState, SETTINGS } from "../model-server/local-state";
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
import { makePasswordManagerClient, makeStateBridge } from "../utils";

/** The cheapest vector in the set to unlock; none of these cases turns on the account version. */
const vector = MIGRATION_CASES[0][1];

describe("key connector migration", () => {
  let harness: MigrationHarness;

  afterEach(() => assertMigrationHarnessClean(harness));

  it(
    "updates the existing key with PUT when the connector already holds one",
    async () => {
      // The connector rejects a PUT for a key that does not exist and a POST for one that does, so
      // picking the wrong verb here fails the migration outright.
      harness = setupMigration(vector);
      const { api, keyConnector } = harness;
      const preexisting = Buffer.alloc(KEY_CONNECTOR_KEY_BYTES, 7).toString("base64");
      keyConnector.seedKey(preexisting);

      const local = new LocalState();
      await syncToLocalState(api, vector.account.email, local);
      const client = await local.unlock(unlockMethodFor(api, vector.account.email));
      await client.user_crypto_management().migrate_to_key_connector(KEY_CONNECTOR_URL);

      // The connector rejects a POST when a key already exists, so the migration completing at all is
      // what shows the client read first and chose PUT. And the key it stores is its own new one, not
      // the key the connector already had.
      expect(keyConnector.key()).not.toBe(preexisting);
      expect(keyConnector.key()).toBeTruthy();
    },
    MIGRATION_TIMEOUT,
  );

  it(
    "sends nothing at all when the client is locked",
    async () => {
      // No `initialize_user_crypto`, so there is no user key to wrap. The migration must fail at
      // step 2, before the freshly minted key connector key has been shown to anyone — otherwise a
      // locked client would leave a usable key sitting at the connector.
      harness = setupMigration();
      const client = makePasswordManagerClient(makeStateBridge(), SETTINGS);

      await expect(
        client.user_crypto_management().migrate_to_key_connector(KEY_CONNECTOR_URL),
      ).rejects.toBeDefined();

      expect(harness.servers.requests).toEqual([]);
      expect(harness.keyConnector.key()).toBeUndefined();
    },
    MIGRATION_TIMEOUT,
  );

  it(
    "does not enroll the account when the key connector rejects the key",
    async () => {
      // The invariant that protects against permanent lockout: if the server recorded the account as
      // key-connector-unlocked while the connector had no key, nothing could ever unlock it again.
      harness = setupMigration(vector);
      const { api, keyConnector } = harness;
      keyConnector.failWrites(500);

      const local = new LocalState();
      await syncToLocalState(api, vector.account.email, local);
      const client = await local.unlock(unlockMethodFor(api, vector.account.email));
      await expect(
        client.user_crypto_management().migrate_to_key_connector(KEY_CONNECTOR_URL),
      ).rejects.toBeDefined();

      // Neither side changed: no key stored, and — the invariant that matters — no enrolment recorded.
      // If the account were enrolled while the connector held no key, nothing could unlock it again.
      expect(keyConnector.key()).toBeUndefined();
      expect(api.db.user(api.soleUserId()).keyConnectorKeyWrappedUserKey).toBeUndefined();
    },
    MIGRATION_TIMEOUT,
  );

  it(
    "surfaces a failure to enroll, after the key connector has already stored the key",
    async () => {
      // Override just the enrolment endpoint to fail, leaving the rest of the model intact.
      harness = setupMigration(vector, {
        "POST /accounts/key-connector/enroll": () => ({
          status: 500,
          json: { message: "enrolment unavailable" },
        }),
      });
      const { api, keyConnector } = harness;

      const local = new LocalState();
      await syncToLocalState(api, vector.account.email, local);
      const client = await local.unlock(unlockMethodFor(api, vector.account.email));
      await expect(
        client.user_crypto_management().migrate_to_key_connector(KEY_CONNECTOR_URL),
      ).rejects.toBeDefined();

      // Documenting real behaviour rather than endorsing it: the key is already at the connector at
      // this point and is not rolled back. That is the safe way round — the account still unlocks by
      // master password, and a retry overwrites the orphaned key via PUT.
      expect(keyConnector.key()).toBeDefined();
      expect(api.db.user(api.soleUserId()).keyConnectorKeyWrappedUserKey).toBeUndefined();
    },
    MIGRATION_TIMEOUT,
  );
});
