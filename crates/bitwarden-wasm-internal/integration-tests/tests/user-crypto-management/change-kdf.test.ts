import {
  Kdf,
  SecureNoteType,
  isChangeKdfError,
  type CipherViewType,
  type PasswordManagerClient,
} from "@bitwarden/sdk-internal";

import type { ClientEmulator } from "../../client-emulator/client-emulator";

import { testHarness, type TestHarness } from "../../test-harness";
import { MASTER_PASSWORD_ACCOUNT } from "../../vectors/accounts";
import { rejection, TEST_EMAIL, TEST_KDF_PARAMS, TEST_PASSWORD } from "../utils";

const NEW_PBKDF2: Kdf = { pBKDF2: { iterations: 700_000 } };
const NEW_ARGON2: Kdf = { argon2id: { iterations: 3, memory: 16, parallelism: 4 } };
const BELOW_MINIMUM: Kdf = { argon2id: { iterations: 1, memory: 16, parallelism: 1 } };

const TIMEOUT = 60_000;

const SECURE_NOTE: CipherViewType = { secureNote: { type: SecureNoteType.Generic } };

describe("change kdf", () => {
  let harness: TestHarness;
  let client: ClientEmulator;
  let passwordManagerClient: PasswordManagerClient;
  let email: string;

  beforeEach(async () => {
    harness = testHarness();
    email = harness.server.seedUser(MASTER_PASSWORD_ACCOUNT).email;

    client = harness.newClientEmulator();
    await client.login(email);
    await client.unlock(TEST_PASSWORD);
    passwordManagerClient = client.getPasswordManagerClient();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /** An item to read back after the change, since a KDF change must leave the vault alone. */
  function createNote(name: string) {
    return passwordManagerClient.vault().ciphers().create({
      organizationId: undefined,
      collectionIds: [],
      folderId: undefined,
      name,
      notes: "untouched by the kdf change",
      favorite: false,
      reprompt: 0,
      type: SECURE_NOTE,
      fields: [],
    });
  }

  /** The single cipher a client's local state holds. */
  function syncedCipher(emulator: ClientEmulator) {
    const [cipher] = emulator.local.ciphers.dump();
    if (cipher === undefined) {
      throw new Error("the sync handed the client no ciphers");
    }

    return cipher;
  }

  test.each([
    { name: "pbkdf2", kdf: NEW_PBKDF2 },
    { name: "argon2id", kdf: NEW_ARGON2 },
  ])(
    "change kdf to $name",
    async ({ kdf }) => {
      const userKey = await passwordManagerClient.crypto().get_user_encryption_key();

      // 1. Change the KDF
      await passwordManagerClient.user_crypto_management().change_kdf(TEST_PASSWORD, kdf);

      // 2. Verify local state is fine: Lock & unlock
      await client.lock();
      await client.unlock(TEST_PASSWORD);
      const lockUnlockSdk = client.getPasswordManagerClient();
      expect(await client.bridge.get_kdf_config()).toEqual(kdf);

      // 3. Verify server state is fine: Sync from new cliend and unlock
      const reloginClient = harness.newClientEmulator();
      await reloginClient.login(email);
      await reloginClient.unlock(TEST_PASSWORD);
      const reloginSdk = reloginClient.getPasswordManagerClient();

      // 4. Verify the new KDF values reached the new client through the sync
      expect(await reloginClient.bridge.get_kdf_config()).toEqual(kdf);

      // 5. Verify the encryption key has not changed
      expect(await lockUnlockSdk.crypto().get_user_encryption_key()).toBe(userKey);
      expect(await reloginSdk.crypto().get_user_encryption_key()).toBe(userKey);
    },
    TIMEOUT,
  );

  describe("failures", () => {
    it(
      "changes nothing when the new KDF is below the allowed minimum",
      async () => {
        // 1. Change the KDF to settings the SDK must refuse before asking the server
        const error = await rejection(
          passwordManagerClient.user_crypto_management().change_kdf(TEST_PASSWORD, BELOW_MINIMUM),
          isChangeKdfError,
        );

        // 2. Verify the SDK refused it
        expect(error.variant).toBe("MasterPassword");

        // 3. Verify neither side moved
        expect(harness.server.getUser(TEST_EMAIL).kdf).toEqual(TEST_KDF_PARAMS);
        expect(await client.bridge.get_kdf_config()).toEqual(TEST_KDF_PARAMS);
      },
      TIMEOUT,
    );
  });

  describe("two unlocked devices, one changes the kdf", () => {
    it(
      "second device can read the vault after the first device changes the kdf",
      async () => {
        // 1. Two unlocked clients, and a kdf change by the first
        const created = await createNote("read again after the kdf change");
        const second = harness.newClientEmulator();
        await second.login(email);
        await second.unlock(TEST_PASSWORD);

        await passwordManagerClient.user_crypto_management().change_kdf(TEST_PASSWORD, NEW_PBKDF2);
        // Sync is triggered by a push notification usually. In this case we do it manually
        // because push notifications are not implemented in the emulator.
        await second.sync(email);

        // 2. The second session locks and unlocks, picking up the new kdf and unlock data the sync
        //    brought down
        await second.lock();
        await second.unlock(TEST_PASSWORD);

        // 3. Verify the vault reads, with the plaintext unchanged. A kdf change re-wraps the user
        //    key without replacing it, so nothing in the vault had to be re-encrypted.
        const view = await second
          .getPasswordManagerClient()
          .vault()
          .ciphers()
          .decrypt(syncedCipher(second));
        expect(view.name).toBe(created.name);
        expect(view.notes).toBe(created.notes);
        expect(await second.bridge.get_kdf_config()).toEqual(NEW_PBKDF2);
      },
      TIMEOUT,
    );
  });
});
