import {
  SecureNoteType,
  type CipherViewType,
  type PasswordManagerClient,
} from "@bitwarden/sdk-internal";

import type { ClientEmulator } from "../../client-emulator/client-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { loadUserVectors, toSeedAccount, userVector } from "../../vectors/load";

/** A V1 master-password account, cheap to unlock, so a case costs the rotation rather than the KDF. */
const VECTOR = userVector(loadUserVectors(), "v1-pbkdf2-min-iterations");
const ACCOUNT = toSeedAccount(VECTOR);
const PASSWORD = VECTOR.account.password;

const TIMEOUT = 120_000;

const SECURE_NOTE: CipherViewType = { secureNote: { type: SecureNoteType.Generic } };

describe("rotate user keys", () => {
  let harness: TestHarness;
  let client: ClientEmulator;
  let passwordManagerClient: PasswordManagerClient;
  let email: string;

  beforeEach(async () => {
    harness = testHarness();
    email = harness.server.seedUser(ACCOUNT).email;

    client = harness.newClientEmulator();
    await client.login(email);
    await client.unlock(PASSWORD);
    passwordManagerClient = client.getPasswordManagerClient();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /** Rotates with the account's password, either upgrading to V2 or carrying V2 forward. */
  function rotate(
    sdk: PasswordManagerClient,
    upgradeTokenAction: "CreateIfNeeded" | "Skip",
  ): Promise<void> {
    return sdk.user_crypto_management().rotate_user_keys({
      key_rotation_method: { Password: { password: PASSWORD } },
      trusted_emergency_access_public_keys: [],
      trusted_organization_public_keys: [],
      upgrade_token_action: upgradeTokenAction,
    });
  }

  /** An item to carry across the rotation, which re-encrypts the vault under the new key. */
  function createNote(name: string) {
    return passwordManagerClient.vault().ciphers().create({
      organizationId: undefined,
      collectionIds: [],
      folderId: undefined,
      name,
      notes: "carried across the rotation",
      favorite: false,
      reprompt: 0,
      type: SECURE_NOTE,
      fields: [],
    });
  }

  /** The named cipher in a client's local state. The account also holds the vector's own items. */
  function syncedCipher(emulator: ClientEmulator, id: string) {
    const cipher = emulator.local.ciphers.dump().find((candidate) => String(candidate.id) === id);
    if (cipher === undefined) {
      throw new Error(`the sync handed the client no cipher ${id}`);
    }

    return cipher;
  }

  /** Logs a client in from nothing and decrypts one of the ciphers the account holds. */
  async function returningView(id: string) {
    const returning = harness.newClientEmulator();
    await returning.login(email);
    await returning.unlock(PASSWORD);

    return await returning
      .getPasswordManagerClient()
      .vault()
      .ciphers()
      .decrypt(syncedCipher(returning, id));
  }

  it(
    "upgrades a V1 account to V2",
    async () => {
      const created = await createNote("before the upgrade");
      const before = harness.server.getUser(email);
      const unlockBefore = before.masterPasswordUnlock;

      // 1. Rotate, asking for an upgrade token
      await rotate(passwordManagerClient, "CreateIfNeeded");

      // 2. Verify the server holds a V2 account
      const stored = harness.server.getUser(email);
      expect(stored.accountCryptographicState).toHaveProperty("V2");
      expect(stored.userKeyId).toMatch(/^[0-9a-f]{32}$/);
      expect(stored.masterPasswordUnlock?.masterKeyWrappedUserKey).not.toBe(
        unlockBefore?.masterKeyWrappedUserKey,
      );

      // 3. Verify the upgrade token is there
      expect(stored.upgradeToken).toBeDefined();

      // 4. Verify local state was updated too — this is the only rotation that writes it
      expect(await client.bridge.get_account_cryptographic_state()).toEqual(
        stored.accountCryptographicState,
      );
      expect(await client.bridge.get_v2_upgrade_token()).toEqual(stored.upgradeToken);

      // 5. Verify a returning client still reads the vault
      expect((await returningView(String(created.id))).name).toBe(created.name);
    },
    TIMEOUT,
  );

  it(
    "rotates an already-V2 account",
    async () => {
      const created = await createNote("before the second rotation");

      // 1. Upgrade to V2, so the second rotation starts from a V2 key
      await rotate(passwordManagerClient, "CreateIfNeeded");
      const upgraded = harness.server.getUser(email);
      const stateAfterUpgrade = upgraded.accountCryptographicState;
      const keyIdAfterUpgrade = upgraded.userKeyId;

      // 2. Log in again on the upgraded account. A rotation leaves the client needing a full sync,
      //    which is exactly what the next one starts from.
      const upgradedClient = harness.newClientEmulator();
      await upgradedClient.login(email);
      await upgradedClient.unlock(PASSWORD);

      // 3. Rotate again, this time without an upgrade token
      await rotate(upgradedClient.getPasswordManagerClient(), "Skip");

      // 4. Verify the account moved on again
      const stored = harness.server.getUser(email);
      expect(stored.accountCryptographicState).not.toEqual(stateAfterUpgrade);
      expect(stored.userKeyId).not.toEqual(keyIdAfterUpgrade);

      // 5. Verify no upgrade token is left: there is nothing left to upgrade
      expect(stored.upgradeToken).toBeUndefined();

      // 6. Verify a returning client still reads the vault
      expect((await returningView(String(created.id))).name).toBe(created.name);
    },
    TIMEOUT,
  );

  describe("two unlocked devices, one rotates", () => {
    it(
      "second device can read the vault after first device rotates",
      async () => {
        // 1. Two unlocked clients, and a rotation by the first
        const created = await createNote("read again after unlocking");
        const second = harness.newClientEmulator();
        await second.login(email);
        await second.unlock(PASSWORD);

        await rotate(passwordManagerClient, "CreateIfNeeded");
        // Sync is triggered by a push notification usually. In this case we do it manually
        // because push notifications are not implemented in the emulator.
        await second.sync(email);

        // Quirk: Clients re-generate the vault like this, mobile calls reinit crypto. This will
        // eventually need to be replaced by re-initing from withhin sync
        //
        // 2. The second session locks and unlocks, picking up the new key from the unlock data and
        //    upgrade token the sync brought down
        await second.lock();
        await second.unlock(PASSWORD);

        // 3. Verify the vault reads again, with the plaintext unchanged
        const view = await second
          .getPasswordManagerClient()
          .vault()
          .ciphers()
          .decrypt(syncedCipher(second, String(created.id)));
        expect(view.name).toBe(created.name);
        expect(view.notes).toBe(created.notes);
      },
      TIMEOUT,
    );
  });
});
