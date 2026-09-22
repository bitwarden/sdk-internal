import { isEncryptionSettingsError, type PasswordManagerClient } from "@bitwarden/sdk-internal";

import { LoginMethod, type ClientEmulator } from "../../client-emulator/client-emulator";
import { IGNORED_FIELDS, validateVault } from "../../client-emulator/validate";
import type { SeededTestVector } from "../../server-emulator/server-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import { asKeyId } from "../type-assertion-helpers";
import { rejection, TEST_PIN } from "../utils";

const TIMEOUT = 120_000;

const V1_VECTOR = testVectors.users.withMasterPassword().get("v1-pbkdf2-min-iterations");
const V2_VECTOR = testVectors.users.withMasterPassword().get("v2-pbkdf2-blob");

const ROTATED_FIELDS = [...IGNORED_FIELDS, "key"];

/**
 * - `v1-pbkdf2-password` carries a V0 attachment, which has no key. The SDK refuses to rotate until
 *   it is re-uploaded, which is the documented precondition rather than a failure.
 */
const NOT_ROTATABLE = ["v1-pbkdf2-password"];

/** Enough consecutive rotations that a second one cannot pass by reusing the first one's state. */
const ROTATION_COUNT = 3;

/** A key id the account never had, to tell "refused the downgrade" from "ignored the payload". */
const REPLAYED_KEY_ID = asKeyId("0f0e0d0c0b0a09080706050403020100");

describe("rotate user keys", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /** Rotates with the account's password, either upgrading to V2 or carrying V2 forward. */
  async function rotate(
    sdk: PasswordManagerClient,
    password: string,
    upgradeTokenAction: "CreateIfNeeded" | "Skip",
  ): Promise<void> {
    await sdk.user_crypto_management().rotate_user_keys({
      key_rotation_method: { Password: { password } },
      trusted_emergency_access_public_keys: [],
      trusted_organization_public_keys: [],
      upgrade_token_action: upgradeTokenAction,
    });
  }

  /**
   * Asserts the whole recorded vault still decrypts, item for item.
   *
   * A rotation re-encrypts every item under the new user key, so this is the assertion that it
   * carried the plaintext across rather than merely leaving something readable behind.
   */
  function assertVaultDecrypts(client: ClientEmulator, seeded: SeededTestVector): Promise<void> {
    return validateVault(client, seeded.seed, ROTATED_FIELDS);
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
      const seeded = harness.server.seedUserTestVector(V1_VECTOR);
      const client = harness.newClientEmulator();
      await client.login(seeded.email, LoginMethod.Password, V1_VECTOR.account.password);
      await client.unlock(V1_VECTOR.account.password);

      // 1. Rotate, asking for an upgrade token
      await rotate(client.getPasswordManagerClient(), V1_VECTOR.account.password, "CreateIfNeeded");

      // 2. Verify the rotating client still reads the vault, over the key it rotated to: sync
      //    down the re-encrypted vault, then re-initialize onto the new key.
      await client.sync(seeded.email);
      await client.reinit();
      await assertVaultDecrypts(client, seeded);

      // 3. Verify a client that logs in reads the vault too
      const reloginClient = harness.newClientEmulator();
      await reloginClient.login(seeded.email, LoginMethod.Password, V1_VECTOR.account.password);
      await reloginClient.unlock(V1_VECTOR.account.password);
      await assertVaultDecrypts(reloginClient, seeded);
    },
    TIMEOUT,
  );

  /**
   * A rotation starting from an account that is already V2. Nothing is upgraded, and the
   * vault still travels to the new key.
   *
   *   client  ──unlock(K1)────────▶ rotate──▶ K2 ──sync ─▶ lock ─▶ unlock(K2) ──▶ reads
   *                                             │
   *   server  ──────────────────────────────── V2 ──▶ V2, vault re-encrypted to K2
   *                                             │
   *   relogin ──────────────────────────────────┴── login ─▶ unlock(K2) ─────────▶ reads
   */
  it(
    "rotates an already-V2 account",
    async () => {
      const seeded = harness.server.seedUserTestVector(V2_VECTOR);
      const client = harness.newClientEmulator();
      await client.login(seeded.email, LoginMethod.Password, V2_VECTOR.account.password);
      await client.unlock(V2_VECTOR.account.password);

      // 1. Rotate without an upgrade token
      await rotate(client.getPasswordManagerClient(), V2_VECTOR.account.password, "Skip");

      // 2. Verify the rotating client still reads the vault, over the key it rotated to. A
      //    V2 to V2 rotation issues no upgrade token, so there is nothing to re-initialize from:
      //    the session restarts instead, syncing the re-encrypted vault and unlocking onto K2.
      await client.sync(seeded.email);
      await client.lock();
      await client.unlock(V2_VECTOR.account.password);
      await assertVaultDecrypts(client, seeded);

      // 3. Verify a client that logs in reads the vault too
      const reloginClient = harness.newClientEmulator();
      await reloginClient.login(seeded.email, LoginMethod.Password, V2_VECTOR.account.password);
      await reloginClient.unlock(V2_VECTOR.account.password);
      await assertVaultDecrypts(reloginClient, seeded);
    },
    TIMEOUT,
  );

  /**
   * Every rotatable account survives being rotated repeatedly.
   *
   *   K0 ──rotate──▶ K1 ──rotate──▶ K2 ──rotate──▶ K3 ──▶ vault still decrypts, fresh login reads it
   */
  // Only a master-password account rotates by password. The other unlock methods rotate through
  // `KeyRotationMethod` variants of their own, which this suite does not drive.
  testVectors.users
    .withMasterPassword()
    .except(...NOT_ROTATABLE)
    .each(
      `$name survives ${ROTATION_COUNT} consecutive rotations`,
      async (vector) => {
        const seeded = harness.server.seedUserTestVector(vector);
        const client = harness.newClientEmulator();
        await client.login(seeded.email, LoginMethod.Password, vector.account.password);
        await client.unlock(vector.account.password);

        // 1. Rotate repeatedly, restarting the session onto each new key before the next one. The
        //    user key is read back every round, so a rotation that left the key untouched is caught
        //    here rather than by the vault assertion below, which a no-op rotation would also pass.
        const userKeys = [
          await client.getPasswordManagerClient().crypto().get_user_encryption_key(),
        ];

        for (let round = 0; round < ROTATION_COUNT; round++) {
          await rotate(
            client.getPasswordManagerClient(),
            vector.account.password,
            "CreateIfNeeded",
          );

          await client.sync(seeded.email);
          await client.lock();
          await client.unlock(vector.account.password);

          userKeys.push(await client.getPasswordManagerClient().crypto().get_user_encryption_key());
        }

        // 2. Verify every round produced a unique key. Set deduplicates items
        // so comparing set length to array length will show if there were duplicates
        expect(new Set(userKeys).size).toBe(userKeys.length);

        // 3. Verify the account ended up V2, whichever version it started at
        expect(await client.bridge.get_account_cryptographic_state()).toHaveProperty("V2");

        // 4. Verify the vault still decrypts to what the vector records, over the last key
        await assertVaultDecrypts(client, seeded);

        // 5. Verify a client that logs in fresh reads it too, so the rotations left the server
        //    holding a consistent account and not just this session
        const reloginClient = harness.newClientEmulator();
        await reloginClient.login(seeded.email, LoginMethod.Password, vector.account.password);
        await reloginClient.unlock(vector.account.password);
        await assertVaultDecrypts(reloginClient, seeded);
      },
      TIMEOUT,
    );

  /**
   * An upgrade rotation carries PIN unlock across, for either lock type and either way a device
   * picks the upgrade up. The upgrade token migrates the PIN enrollment to the new key.
   *
   *   device   ──unlock(K1)─▶ set_pin ─┬── sync ─▶ [reinit(K2)] ─▶ restart ─▶ unlock(PIN) ──▶ reads
   *                                    │
   *   server   ────────────────── K1 ──▶ K2, vault re-encrypted, token issued
   *                                    │
   *   rotating ──unlock(K1)──────── rotate
   *
   * - `BeforeFirstUnlock` keeps a persistent envelope, so the PIN unlocks straight after restart.
   * - `AfterFirstUnlock` keeps only the encrypted PIN; a password unlock rebuilds the envelope.
   * - `reinit` picks the upgrade up in the running session; `restart` only on the next unlock.
   */
  for (const lockType of ["BeforeFirstUnlock", "AfterFirstUnlock"] as const) {
    for (const pickup of ["reinit", "restart"] as const) {
      it(
        `${lockType} pin unlock survives an upgrade picked up by ${pickup}`,
        async () => {
          // 1. A device enrolled in PIN unlock
          const seeded = harness.server.seedUserTestVector(V1_VECTOR);
          const device = harness.newClientEmulator();
          await device.login(seeded.email, LoginMethod.Password, V1_VECTOR.account.password);
          await device.unlock(V1_VECTOR.account.password);
          await device
            .getPasswordManagerClient()
            .user_crypto_management()
            .pin_settings()
            .set_pin(TEST_PIN, lockType);

          // 2. A second device upgrades the user to v2 encryption
          const rotatingDevice = harness.newClientEmulator();
          await rotatingDevice.login(seeded.email, LoginMethod.Password, V1_VECTOR.account.password);
          await rotatingDevice.unlock(V1_VECTOR.account.password);
          await rotate(
            rotatingDevice.getPasswordManagerClient(),
            V1_VECTOR.account.password,
            "CreateIfNeeded",
          );

          // 3. The first device picks the upgrade up the way a push notification would
          await device.sync(seeded.email);
          if (pickup === "reinit") {
            await device.reinit();
          }

          // 4. Simulate lock and unlock
          await device.lock();
          await device.unlockWith({ pinState: { pin: TEST_PIN } });

          // 5. Simulate restart
          await device.restart();
          if (lockType === "BeforeFirstUnlock") {
            // In BFU mode, after a restart, we can unlock with pin
            await device.unlockWith({ pinState: { pin: TEST_PIN } });
          } else {
            // In AFU mode, after a restart, we cannot unlock with pin
            const error = await rejection(
              device.unlockWith({ pinState: { pin: TEST_PIN } }),
              isEncryptionSettingsError,
            );
            expect(error.variant).toBe("PinUnlockNotAvailable");
            await device.unlock(V1_VECTOR.account.password);
            await device.lock();
            await device.unlockWith({ pinState: { pin: TEST_PIN } });
          }

          // 6. Verify the PIN is available and unlocks
          const pinSettings = () =>
            device.getPasswordManagerClient().user_crypto_management().pin_settings();
          expect(await pinSettings().get_status()).toBe("Available");
          await device.unlockWith({ pinState: { pin: TEST_PIN } });

          // 7. Verify the PIN enrollment moved to the new key, and the vault reads
          expect(await pinSettings().get_pin()).toBe(TEST_PIN);
          await assertVaultDecrypts(device, seeded);
        },
        TIMEOUT,
      );
    }
  }

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
      const seeded = harness.server.seedUserTestVector(V1_VECTOR);
      const client = harness.newClientEmulator();
      await client.login(seeded.email, LoginMethod.Password, V1_VECTOR.account.password);
      await client.unlock(V1_VECTOR.account.password);
      const second = harness.newClientEmulator();
      await second.login(seeded.email, LoginMethod.Password, V1_VECTOR.account.password);
      await second.unlock(V1_VECTOR.account.password);

      await rotate(client.getPasswordManagerClient(), V1_VECTOR.account.password, "CreateIfNeeded");
      // Sync is triggered by a push notification usually. In this case we do it manually
      // because push notifications are not implemented in the emulator.
      await second.sync(seeded.email);

      // 2. The second session re-initializes onto the key material the sync brought down, which
      //    is what a client does instead of tearing itself down and unlocking again
      await second.reinit();

      // 3. Verify the vault reads again, with the plaintext unchanged
      await assertVaultDecrypts(second, seeded);
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
      const { email } = harness.server.seedUserTestVector(V1_VECTOR);
      const rotatingDevice = harness.newClientEmulator();
      await rotatingDevice.login(email, LoginMethod.Password, V1_VECTOR.account.password);
      await rotatingDevice.unlock(V1_VECTOR.account.password);
      const otherDevice = harness.newClientEmulator();
      await otherDevice.login(email, LoginMethod.Password, V1_VECTOR.account.password);
      await otherDevice.unlock(V1_VECTOR.account.password);

      const v1State = harness.server.getUser(email).accountCryptographicState;

      // 2. One device upgrades the account, and both pick the upgrade up
      await rotate(
        rotatingDevice.getPasswordManagerClient(),
        V1_VECTOR.account.password,
        "CreateIfNeeded",
      );
      await rotatingDevice.sync(email);
      await rotatingDevice.reinit();
      await otherDevice.sync(email);
      await otherDevice.reinit();

      const upgradedState = await rotatingDevice.bridge.get_account_cryptographic_state();
      expect(upgradedState).toHaveProperty("V2");
      const upgradedKeyId = await rotatingDevice.bridge.get_user_key_id();

      // 3. The server replays the state it held before the upgrade
      const stored = harness.server.getUser(email);
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
