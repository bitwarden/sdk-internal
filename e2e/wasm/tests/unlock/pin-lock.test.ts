import { isEncryptionSettingsError } from "@bitwarden/sdk-internal";

import { validateVault } from "../../client-emulator/validate";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import { rejection, TEST_PIN } from "../utils";

const TIMEOUT = 120_000;

const V2_VECTOR = testVectors.users.withMasterPassword().get("v2-pbkdf2-blob");

const WRONG_PIN = "0000";

describe("pin lock", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /**
   * A BeforeFirstUnlock PIN keeps a persistent envelope, so it unlocks straight after the app
   * restarts, both from the encrypted PIN and from the envelope itself.
   *
   *   device ──unlock─▶ set_pin ─▶ restart ─▶ unlock(PIN state) ─▶ restart ─▶ unlock(envelope)
   */
  testVectors.users.each(
    "$name unlocks with a BeforeFirstUnlock PIN after a restart",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const device = await harness.newUnlockedClient(seeded);

      // 1. Enroll the PIN
      await device
        .getPasswordManagerClient()
        .user_crypto_management()
        .pin_settings()
        .set_pin(TEST_PIN, "BeforeFirstUnlock");

      // 2. Verify the PIN unlocks after a restart
      await device.restart();
      await device.unlockWith({ pinState: { pin: TEST_PIN } });
      await validateVault(device, seeded.seed, []);

      // 3. Verify the persistent envelope unlocks after a restart too
      const envelope = await device.bridge.get_persistent_pin_envelope();
      await device.restart();
      await device.unlockWith({
        pinEnvelope: { pin: TEST_PIN, pin_protected_user_key_envelope: envelope! },
      });
      await validateVault(device, seeded.seed, []);
    },
    TIMEOUT,
  );

  /**
   * An AfterFirstUnlock PIN keeps only an ephemeral envelope: it unlocks a locked app, but not a
   * restarted one until another unlock method has run.
   *
   *   device ──unlock─▶ set_pin ─▶ lock ─▶ unlock(PIN) ─▶ restart ─▶ unlock(PIN) refused
   */
  testVectors.users.each(
    "$name unlocks with an AfterFirstUnlock PIN until a restart",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const device = await harness.newUnlockedClient(seeded);

      // 1. Enroll the PIN
      await device
        .getPasswordManagerClient()
        .user_crypto_management()
        .pin_settings()
        .set_pin(TEST_PIN, "AfterFirstUnlock");

      // 2. Verify the PIN unlocks a locked app
      await device.lock();
      await device.unlockWith({ pinState: { pin: TEST_PIN } });
      await validateVault(device, seeded.seed, []);

      // 3. Verify the PIN is refused after a restart
      await device.restart();
      const error = await rejection(
        device.unlockWith({ pinState: { pin: TEST_PIN } }),
        isEncryptionSettingsError,
      );
      expect(error.variant).toBe("PinUnlockNotAvailable");
    },
    TIMEOUT,
  );

  it(
    "validates the PIN",
    async () => {
      const seeded = harness.server.seedUserTestVector(V2_VECTOR);
      const device = await harness.newUnlockedClient(seeded);
      const pinSettings = device.getPasswordManagerClient().user_crypto_management().pin_settings();

      // 1. Enroll the PIN
      await pinSettings.set_pin(TEST_PIN, "BeforeFirstUnlock");

      // 2. Verify only the enrolled PIN validates
      expect(await pinSettings.validate_pin(TEST_PIN)).toBe(true);
      expect(await pinSettings.validate_pin(WRONG_PIN)).toBe(false);
    },
    TIMEOUT,
  );

  it(
    "unsets the PIN",
    async () => {
      const seeded = harness.server.seedUserTestVector(V2_VECTOR);
      const device = await harness.newUnlockedClient(seeded);
      const pinSettings = device.getPasswordManagerClient().user_crypto_management().pin_settings();

      // 1. Enroll the PIN, then unset it
      await pinSettings.set_pin(TEST_PIN, "BeforeFirstUnlock");
      await pinSettings.unset_pin();

      // 2. Verify the PIN no longer unlocks
      await device.restart();
      const error = await rejection(
        device.unlockWith({ pinState: { pin: TEST_PIN } }),
        isEncryptionSettingsError,
      );
      expect(error.variant).toBe("PinUnlockNotAvailable");
    },
    TIMEOUT,
  );

  it(
    "stores the PIN length on set and clears it on unset",
    async () => {
      const seeded = harness.server.seedUserTestVector(V2_VECTOR);
      const device = await harness.newUnlockedClient(seeded);
      const pinSettings = device.getPasswordManagerClient().user_crypto_management().pin_settings();

      // 1. Enroll the PIN, and verify the length is stored
      await pinSettings.set_pin(TEST_PIN, "AfterFirstUnlock");
      expect(await pinSettings.get_pin_length()).toBe(TEST_PIN.length);

      // 2. Unset the PIN, and verify the length is gone
      await pinSettings.unset_pin();
      expect(await pinSettings.get_pin_length()).toBeUndefined();
    },
    TIMEOUT,
  );

  /**
   * A PIN set by a client that predates stored PIN lengths has none. The first PIN unlock
   * records it.
   */
  it(
    "stores the length of a PIN set before lengths were, on unlock",
    async () => {
      const seeded = harness.server.seedUserTestVector(V2_VECTOR);
      const device = await harness.newUnlockedClient(seeded);

      // 1. Enroll the PIN as an older client would have, with no length stored
      await device
        .getPasswordManagerClient()
        .user_crypto_management()
        .pin_settings()
        .set_pin(TEST_PIN, "BeforeFirstUnlock");
      await device.bridge.clear_pin_length();

      // 2. Unlock with the PIN
      await device.restart();
      await device.unlockWith({ pinState: { pin: TEST_PIN } });

      // 3. Verify the length was recorded
      const pinSettings = device.getPasswordManagerClient().user_crypto_management().pin_settings();
      expect(await pinSettings.get_pin_length()).toBe(TEST_PIN.length);
    },
    TIMEOUT,
  );
});
