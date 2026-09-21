import {
  SecureNoteType,
  type CipherViewType,
  type PasswordManagerClient,
  type CipherView,
} from "@bitwarden/sdk-internal";

import { testHarness, type TestHarness } from "../../test-harness";
import type { ClientEmulator } from "../../client-emulator/client-emulator";
import { asKeyId } from "../type-assertion-helpers";
import { MASTER_PASSWORD_ACCOUNT } from "../../vectors/accounts";
import { TEST_EMAIL, TEST_PASSWORD, TEST_PIN } from "../utils";

const TIMEOUT = 120_000;

const SECURE_NOTE: CipherViewType = { secureNote: { type: SecureNoteType.Generic } };

const NOTE_NAME = "seeded before the rotation";
const NOTE_CONTENT = "carried across the rotation";

/** A key id the account never had, to tell "refused the downgrade" from "ignored the payload". */
const REPLAYED_KEY_ID = asKeyId("0f0e0d0c0b0a09080706050403020100");

describe("rotate user keys", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /** Rotates with the account's password, either upgrading to V2 or carrying V2 forward. */
  function rotate(
    sdk: PasswordManagerClient,
    upgradeTokenAction: "CreateIfNeeded" | "Skip",
  ): Promise<void> {
    return sdk.user_crypto_management().rotate_user_keys({
      key_rotation_method: { Password: { password: TEST_PASSWORD } },
      trusted_emergency_access_public_keys: [],
      trusted_organization_public_keys: [],
      upgrade_token_action: upgradeTokenAction,
    });
  }

  /**
   * Seeds a V1 account — what a master-password account starts out as — holding the one note the
   * tests carry across the rotation. The client that seeded it is dropped; tests log in fresh.
   */
  async function seedV1(): Promise<string> {
    // Will be replaced by test vectors
    const { email } = harness.server.seedUser(MASTER_PASSWORD_ACCOUNT);

    const seeding = harness.newClientEmulator();
    await seeding.login(email);
    await seeding.unlock(TEST_PASSWORD);
    await createNote(seeding.getPasswordManagerClient());

    return email;
  }

  /**
   * Seeds a V2 account.
   *
   * No seed vector holds a V2 account that unlocks with a master password, so one is rotated up to
   * V2 here and the client that did it is dropped — a test starts from a fresh login either way.
   */
  async function seedV2(): Promise<string> {
    // Will be replaced by test vectors
    const email = await seedV1();

    const upgrading = harness.newClientEmulator();
    await upgrading.login(email);
    await upgrading.unlock(TEST_PASSWORD);
    await rotate(upgrading.getPasswordManagerClient(), "CreateIfNeeded");

    return email;
  }

  /** The item that has to survive a rotation, which re-encrypts the vault under the new key. */
  function createNote(sdk: PasswordManagerClient): Promise<CipherView> {
    return sdk.vault().ciphers().create({
      organizationId: undefined,
      collectionIds: [],
      folderId: undefined,
      name: NOTE_NAME,
      notes: NOTE_CONTENT,
      favorite: false,
      reprompt: 0,
      type: SECURE_NOTE,
      fields: [],
    });
  }

  /** Reads the seeded note back through a client, asserting the plaintext survived. */
  async function assertVaultDecrypts(client: ClientEmulator): Promise<void> {
    // Will be replaced by test vectors + a full vault assert
    const [cipher] = client.local.ciphers.dump();
    if (cipher === undefined) {
      throw new Error("the sync handed the client no ciphers");
    }

    const view = await client.getPasswordManagerClient().vault().ciphers().get(String(cipher.id));

    expect(view.name).toBe(NOTE_NAME);
    expect(view.notes).toBe(NOTE_CONTENT);
  }

  /**
   * A V1 account rotates up to V2: the vault is re-encrypted under a new user key, and both the
   * session that did it and a fresh login read it back.
   *
   *   client  ──unlock(K1)────────▶ rotate──▶ K2 ──sync ─▶ reinit(K2) ──▶ reads
   *                                             │
   *   server  ────────────────────────────────  V1 ──▶ V2, vault re-encrypted to K2
   *                                             │
   *   relogin ──────────────────────────────────┴── login ─▶ unlock(K2) ─────────▶ reads
   */
  it(
    "upgrades a V1 account to V2",
    async () => {
      const email = await seedV1();
      const client = harness.newClientEmulator();
      await client.login(email);
      await client.unlock(TEST_PASSWORD);

      // 1. Rotate, asking for an upgrade token
      await rotate(client.getPasswordManagerClient(), "CreateIfNeeded");

      // 2. Verify the rotating client still reads the vault, over the key it rotated to: sync
      //    down the re-encrypted vault, then re-initialize onto the new key.
      await client.sync(email);
      await client.reinit();
      await assertVaultDecrypts(client);

      // 3. Verify a client that logs in reads the vault too
      const reloginClient = harness.newClientEmulator();
      await reloginClient.login(email);
      await reloginClient.unlock(TEST_PASSWORD);
      await assertVaultDecrypts(reloginClient);
    },
    TIMEOUT,
  );

  /**
   * A second rotation, starting from an account that is already V2. Nothing is upgraded, and the
   * vault still travels to the new key.
   *
   *   client  ──unlock(K2)────────▶ rotate──▶ K3 ──sync ─▶ lock ─▶ unlock(K3) ──▶ reads
   *                                             │
   *   server  ──────────────────────────────── V2 ──▶ V2, vault re-encrypted to K3
   *                                             │
   *   relogin ──────────────────────────────────┴── login ─▶ unlock(K3) ─────────▶ reads
   */
  it(
    "rotates an already-V2 account",
    async () => {
      const email = await seedV2();
      const client = harness.newClientEmulator();
      await client.login(email);
      await client.unlock(TEST_PASSWORD);

      // 1. Rotate again, this time without an upgrade token
      await rotate(client.getPasswordManagerClient(), "Skip");

      // 2. Verify the rotating client still reads the vault, over the key it rotated to. A
      //    V2 to V2 rotation issues no upgrade token, so there is nothing to re-initialize from:
      //    the session restarts instead, syncing the re-encrypted vault and unlocking onto K3.
      await client.sync(email);
      await client.lock();
      await client.unlock(TEST_PASSWORD);
      await assertVaultDecrypts(client);

      // 3. Verify a client that logs in reads the vault too
      const reloginClient = harness.newClientEmulator();
      await reloginClient.login(email);
      await reloginClient.unlock(TEST_PASSWORD);
      await assertVaultDecrypts(reloginClient);
    },
    TIMEOUT,
  );

  /**
   * An upgrade rotation carries PIN unlock across: the upgrade token migrates the PIN envelope, so
   * the other device still unlocks with the same PIN once the rotation reaches it.
   *
   *   other    ──unlock(K1)─▶ set_pin ────────────┬── sync ─▶ lock ─▶ unlock(PIN) ──▶ reads
   *                                               │
   *   server   ─────────────────────────── K1 ──▶ K2, vault re-encrypted, token issued
   *                                               │
   *   rotating ──unlock(K1)──────────────────rotate ─┘
   */
  it(
    "pin unlock still works after another device rotates",
    async () => {
      // 1. A device enrolled in PIN unlock, holding an envelope that survives a lock
      const email = await seedV1();
      const otherDevice = harness.newClientEmulator();
      await otherDevice.login(email);
      await otherDevice.unlock(TEST_PASSWORD);
      await otherDevice
        .getPasswordManagerClient()
        .user_crypto_management()
        .pin_settings()
        .set_pin(TEST_PIN, "BeforeFirstUnlock");

      // 2. A second device upgrades the user to v2 encryption
      const rotatingDevice = harness.newClientEmulator();
      await rotatingDevice.login(email);
      await rotatingDevice.unlock(TEST_PASSWORD);
      await rotate(rotatingDevice.getPasswordManagerClient(), "CreateIfNeeded");

      // 3. The other device picks the rotation up the way a push notification would, then
      //    restarts onto the new key
      await otherDevice.sync(email);
      await otherDevice.lock();

      // 4. Verify the PIN still unlocks, over the envelope the rotation left in state
      await otherDevice.unlockWith({ pinState: { pin: TEST_PIN } });

      // 5. Verify the vault reads, with the plaintext unchanged
      await assertVaultDecrypts(otherDevice);
    },
    TIMEOUT,
  );

  /**
   * A second session, unlocked before the rotation, is left holding the old user key. It only
   * catches up once a sync brings the new key material down and the session re-initializes:
   *
   *   device 1  ──unlock(K1)──┬──rotate──▶ K2 ────────────────────────────▶ reads (K2)
   *                           │              │
   *   server    ──────────────┴──────────────┴── vault re-encrypted to K2
   *                                          │
   *   device 2  ──unlock(K1)─────────────────┴── sync ─▶ reinit ─────────▶ reads (K2)
   *                                              (stale K1 until here)
   */
  it(
    "second device can read the vault after the first device rotates",
    async () => {
      // 1. Two unlocked clients, and a rotation by the first
      const email = await seedV1();
      const client = harness.newClientEmulator();
      await client.login(email);
      await client.unlock(TEST_PASSWORD);

      const second = harness.newClientEmulator();
      await second.login(email);
      await second.unlock(TEST_PASSWORD);

      await rotate(client.getPasswordManagerClient(), "CreateIfNeeded");
      // Sync is triggered by a push notification usually. In this case we do it manually
      // because push notifications are not implemented in the emulator.
      await second.sync(email);

      // 2. The second session re-initializes onto the key material the sync brought down, which
      //    is what a client does instead of tearing itself down and unlocking again
      await second.reinit();

      // 3. Verify the vault reads again, with the plaintext unchanged
      await assertVaultDecrypts(second);
    },
    TIMEOUT,
  );

  /**
   * SECURITY: We need to prevent a downgrade attack where the server records a V1 state
   * and replays it after the account has been upgraded to V2. This currently only works for
   * logged in accounts. Newly logged in accounts are not prevented from being replayed.
   *
   *   rotating ──unlock(K1)──rotate──▶ K2 ── sync ─▶ reinit ──┬── sync(V1 replay) ──▶ stays V2
   *                                     │                     │
   *   server   ──── V1 ─────────────────┴──▶ V2 ── replays ── V1
   *                                     │                     │
   *   other    ──unlock(K1)──── sync ─▶ reinit ────────────────┴── sync(V1 replay) ──▶ stays V2
   */
  it(
    "refuses a V1 state the server replays after the upgrade",
    async () => {
      // 1. Two unlocked devices on a V1 account, and the state the server holds for it
      const email = await seedV1();
      const rotatingDevice = harness.newClientEmulator();
      await rotatingDevice.login(email);
      await rotatingDevice.unlock(TEST_PASSWORD);

      const otherDevice = harness.newClientEmulator();
      await otherDevice.login(email);
      await otherDevice.unlock(TEST_PASSWORD);

      const v1State = harness.server.getUser(TEST_EMAIL).accountCryptographicState;

      // 2. One device upgrades the account, and both pick the upgrade up
      await rotate(rotatingDevice.getPasswordManagerClient(), "CreateIfNeeded");
      await rotatingDevice.sync(email);
      await rotatingDevice.reinit();
      await otherDevice.sync(email);
      await otherDevice.reinit();

      const upgradedState = await rotatingDevice.bridge.get_account_cryptographic_state();
      expect(upgradedState).toHaveProperty("V2");
      const upgradedKeyId = await rotatingDevice.bridge.get_user_key_id();

      // 3. The server replays the state it held before the upgrade
      const stored = harness.server.getUser(TEST_EMAIL);
      stored.accountCryptographicState = v1State;
      stored.userKeyId = REPLAYED_KEY_ID;

      await rotatingDevice.sync(email);
      await otherDevice.sync(email);

      // 4. Verify neither device took the downgrade
      expect(await rotatingDevice.bridge.get_account_cryptographic_state()).toEqual(upgradedState);
      expect(await otherDevice.bridge.get_account_cryptographic_state()).toEqual(upgradedState);
      expect(await rotatingDevice.bridge.get_user_key_id()).toEqual(upgradedKeyId);
      expect(await otherDevice.bridge.get_user_key_id()).toEqual(upgradedKeyId);
    },
    TIMEOUT,
  );
});
