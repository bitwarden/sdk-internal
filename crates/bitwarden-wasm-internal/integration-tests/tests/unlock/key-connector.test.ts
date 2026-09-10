// Key connector unlock and migration.
//
// The `keyConnector` unlock method takes a key the client already holds; `keyConnectorUrl` has the
// SDK fetch it from the deployment itself. Only the second exercises the key-connector client, so
// these tests drive that one, against the key-connector server emulator.

import { expectedVaultOf, validateLocalState } from "../../client-emulator/validate";
import { KEY_CONNECTOR_URL } from "../../server-emulator/urls";
import { testHarness, type TestHarness } from "../../test-harness";
import { loadUserVectors, toSeedAccount, userVector, type UserVector } from "../../vectors/load";

import type { InitUserCryptoMethod } from "@bitwarden/sdk-internal";

/** A real KDF derivation per unlock. */
const TIMEOUT = 120_000;

const KEY_CONNECTOR_VECTORS = ["v1-pbkdf2-key-connector", "v2-pbkdf2-key-connector"];

/** A V1 master-password account, cheap to unlock, for the migration cases. */
const PASSWORD_VECTOR = userVector(loadUserVectors(), "v1-pbkdf2-min-iterations");

/** The user key wrapped with the account's key-connector key, as the vector records it. */
function wrappedUserKeyOf(vector: UserVector): string {
  for (const method of vector.unlockMethods) {
    if ("keyConnector" in method) {
      return String(method.keyConnector.user_key);
    }
  }

  throw new Error(`user vector ${vector.name} declares no key-connector unlock`);
}

/** The unlock method that has the SDK fetch the key-connector key rather than be handed it. */
function keyConnectorUrlUnlock(wrappedUserKey: string): InitUserCryptoMethod {
  return {
    keyConnectorUrl: {
      url: KEY_CONNECTOR_URL,
      key_connector_key_wrapped_user_key: wrappedUserKey,
    },
  } as InitUserCryptoMethod;
}

describe("key connector", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  });

  afterEach(() => harness.restore());

  describe("unlock via keyConnectorUrl", () => {
    it.each(KEY_CONNECTOR_VECTORS)(
      "%s decrypts its vault after fetching its key from the deployment",
      async (name) => {
        const vector = userVector(loadUserVectors(), name);
        const account = toSeedAccount(vector);

        const { email } = harness.server.seedUser(account);
        const client = harness.newClientEmulator();
        await client.login(email);

        // Nothing has been written, so nothing may differ — not even a restamped field.
        await validateLocalState(
          client.local,
          keyConnectorUrlUnlock(wrappedUserKeyOf(vector)),
          expectedVaultOf(account),
          { ignore: [] },
        );
      },
      TIMEOUT,
    );

    it(
      "refuses to unlock when the deployment holds no key for the account",
      async () => {
        const vector = userVector(loadUserVectors(), "v1-pbkdf2-key-connector");
        const { email } = harness.server.seedUser(toSeedAccount(vector));

        // Take the key back out, as a deployment that has never seen the account.
        harness.server.keyConnector.forgetUserKey(email);

        const client = harness.newClientEmulator();
        await client.login(email);

        await expect(
          client.unlockWith(keyConnectorUrlUnlock(wrappedUserKeyOf(vector))),
        ).rejects.toBeDefined();
        // Nothing was unlocked, so there is no client to drive.
        expect(() => client.getPasswordManagerClient()).toThrow();
      },
      TIMEOUT,
    );
  });

  describe("migrate_to_key_connector", () => {
    it(
      "moves a master-password account onto key connector unlock",
      async () => {
        const account = toSeedAccount(PASSWORD_VECTOR);
        const { email } = harness.server.seedUser(account);

        const client = harness.newClientEmulator();
        await client.login(email);
        await client.unlock(PASSWORD_VECTOR.account.password);
        const userKeyBefore = await client
          .getPasswordManagerClient()
          .crypto()
          .get_user_encryption_key();

        await client
          .getPasswordManagerClient()
          .user_crypto_management()
          .migrate_to_key_connector(KEY_CONNECTOR_URL);

        // The deployment now holds a key, and the server holds the user key wrapped with it.
        expect(harness.server.keyConnector.storedUserKey(email)).not.toBeNull();
        const user = harness.server.getUser(email);
        expect(user.keyConnectorKeyWrappedUserKey).toBeDefined();

        // The migration re-wraps the user key rather than replacing it, and the account no longer
        // has a master password to unlock with.
        expect(await client.getPasswordManagerClient().crypto().get_user_encryption_key()).toEqual(
          userKeyBefore,
        );
        expect(user.masterPasswordUnlock).toBeNull();

        // A client coming from nothing reads the same vault through key connector.
        const returning = harness.newClientEmulator();
        await returning.login(email);
        await validateLocalState(
          returning.local,
          keyConnectorUrlUnlock(String(user.keyConnectorKeyWrappedUserKey)),
          expectedVaultOf(account),
          { ignore: [] },
        );
      },
      TIMEOUT,
    );

    it(
      "replaces a key the deployment already holds",
      async () => {
        const account = toSeedAccount(PASSWORD_VECTOR);
        const { email } = harness.server.seedUser(account);

        // A key already stored, so the migration takes its update branch rather than its create one.
        const stale = "c3RhbGUta2V5LXRoZS1taWdyYXRpb24tbXVzdC1yZXBsYWNlLi4uLi4uLi4=";
        harness.server.keyConnector.seedUserKey(email, stale);

        const client = harness.newClientEmulator();
        await client.login(email);
        await client.unlock(PASSWORD_VECTOR.account.password);

        await client
          .getPasswordManagerClient()
          .user_crypto_management()
          .migrate_to_key_connector(KEY_CONNECTOR_URL);

        expect(harness.server.keyConnector.storedUserKey(email)).not.toEqual(stale);

        const user = harness.server.getUser(email);
        const returning = harness.newClientEmulator();
        await returning.login(email);
        await validateLocalState(
          returning.local,
          keyConnectorUrlUnlock(String(user.keyConnectorKeyWrappedUserKey)),
          expectedVaultOf(account),
          { ignore: [] },
        );
      },
      TIMEOUT,
    );
  });
});
