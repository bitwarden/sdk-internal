import { isDeviceTrustError, isEncryptionSettingsError } from "@bitwarden/sdk-internal";

import { LoginMethod, type ClientEmulator } from "../../client-emulator/client-emulator";
import { DEVICE_IDENTIFIER } from "../../client-emulator/local-state";
import { validateVault } from "../../client-emulator/validate";
import type { DeviceEntity } from "../../server-emulator/entities";
import { testHarness, type TestHarness } from "../../test-harness";
import { asEncString, asUnsignedSharedKey } from "../type-assertion-helpers";
import { testVectors } from "../../vectors/test-vectors";
import { rejection } from "../utils";

/** The account the decline and failure cases run against, where the vector does not matter. */
const V1_VECTOR = testVectors.users.withMasterPassword().get("v1-pbkdf2-min-iterations");

const TIMEOUT = 120_000;

/**
 * Trusting a device during login, then unlocking with it.
 *
 * ```
 *  client                         server
 *  ──────                         ──────
 *  login (registers device) ────▶ device row, no keys
 *  choose Trust
 *  unlock
 *  trust_device_if_required ────▶ PUT /devices/:id/keys
 *  device key ─▶ bridge           device row holds wrapped keys
 *
 *  lock, unlock with trustedDevice(server keys) ─▶ SDK reads device key ─▶ vault decrypts
 * ```
 */
describe("device trust", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  function deviceRow(email: string): DeviceEntity | undefined {
    const user = harness.server.getUser(email);
    const [device] = harness.server.db.devices.filter(
      (candidate) => candidate.userId === user.userId && candidate.identifier === DEVICE_IDENTIFIER,
    );

    return device;
  }

  /** The trusted device keys the server sends with a login response for this device. */
  function trustedDeviceOption(email: string) {
    const device = deviceRow(email);

    return {
      encryptedPrivateKey:
        device?.encryptedPrivateKey == null ? undefined : asEncString(device.encryptedPrivateKey),
      encryptedUserKey:
        device?.encryptedUserKey == null ? undefined : asUnsignedSharedKey(device.encryptedUserKey),
    };
  }

  async function loginAndChoose(
    email: string,
    password: string,
    choice: "Trust" | "DontTrust",
  ): Promise<ClientEmulator> {
    const client = harness.newClientEmulator();
    await client.login(email, LoginMethod.Password, password);
    await client.unlock(password);
    await client.getPasswordManagerClient().device_trust().set_trust_device_choice(choice);

    return client;
  }

  async function trustedClient(email: string, password: string): Promise<ClientEmulator> {
    const client = await loginAndChoose(email, password, "Trust");
    await client.getPasswordManagerClient().device_trust().trust_device_if_required();

    return client;
  }

  testVectors.users.withMasterPassword().each(
    "$name unlocks with the trusted device after trusting",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const client = await loginAndChoose(seeded.email, vector.account.password, "Trust");

      // 1. Trust the device
      const outcome = await client
        .getPasswordManagerClient()
        .device_trust()
        .trust_device_if_required();
      expect(outcome).toBe("Trusted");

      // 2. Verify local state: device key stored, choice consumed
      expect(await client.bridge.get_device_key()).not.toBeNull();
      expect(await client.bridge.get_should_trust_device()).toBeNull();

      // 3. Verify both sides together: lock, then unlock with only the server's keys
      expect(deviceRow(seeded.email)?.encryptedUserKey).toBeTruthy();
      await client.lock();
      await client.unlockWith({ trustedDevice: { option: trustedDeviceOption(seeded.email) } });
      await validateVault(client, seeded.seed);
    },
    TIMEOUT,
  );

  it(
    "does not trust the device when the user declined",
    async () => {
      const seeded = harness.server.seedUserTestVector(V1_VECTOR);
      const client = await loginAndChoose(seeded.email, V1_VECTOR.account.password, "DontTrust");

      // 1. Act
      const outcome = await client
        .getPasswordManagerClient()
        .device_trust()
        .trust_device_if_required();

      // 2. Verify neither side changed
      expect(outcome).toBe("NotRequested");
      expect(await client.bridge.get_device_key()).toBeNull();
      expect(deviceRow(seeded.email)?.encryptedUserKey).toBeNull();
    },
    TIMEOUT,
  );

  it(
    "keeps the choice and no device key when the server rejects the device",
    async () => {
      const seeded = harness.server.seedUserTestVector(V1_VECTOR);
      // The emulator-only login registers no device, so the server answers 404.
      const client = harness.newClientEmulator();
      await client.login(seeded.email, LoginMethod.Unimplemented);
      await client.unlock(V1_VECTOR.account.password);
      const deviceTrust = client.getPasswordManagerClient().device_trust();
      await deviceTrust.set_trust_device_choice("Trust");

      // 1. Act
      const error = await rejection(deviceTrust.trust_device_if_required(), isDeviceTrustError);

      // 2. Verify the failure left the retry possible and nothing half-written
      expect(error.variant).toBe("Api");
      expect(await client.bridge.get_device_key()).toBeNull();
      expect(await client.bridge.get_should_trust_device()).toBe(true);
      expect(deviceRow(seeded.email)).toBeUndefined();
    },
    TIMEOUT,
  );

  it(
    "refuses to unlock an untrusted device",
    async () => {
      const seeded = harness.server.seedUserTestVector(V1_VECTOR);
      const client = harness.newClientEmulator();
      await client.login(seeded.email, LoginMethod.Password, V1_VECTOR.account.password);

      // 1. Act: no device key was ever stored
      const error = await rejection(
        client.unlockWith({ trustedDevice: { option: trustedDeviceOption(seeded.email) } }),
        isEncryptionSettingsError,
      );

      // 2. Verify
      expect(error.variant).toBe("DeviceNotTrusted");
    },
    TIMEOUT,
  );

  it(
    "reports lost trust when the server no longer sends keys",
    async () => {
      const seeded = harness.server.seedUserTestVector(V1_VECTOR);
      const client = await trustedClient(seeded.email, V1_VECTOR.account.password);
      await client.lock();

      // 1. Act: the server dropped the device's keys, as an admin untrusting it would
      const error = await rejection(
        client.unlockWith({
          trustedDevice: {
            option: { encryptedPrivateKey: undefined, encryptedUserKey: undefined },
          },
        }),
        isEncryptionSettingsError,
      );

      // 2. Verify the device told the server and kept its key
      expect(error.variant).toBe("DeviceTrustLost");
      expect(deviceRow(seeded.email)?.lostTrustReported).toBe(true);
      expect(await client.bridge.get_device_key()).not.toBeNull();
    },
    TIMEOUT,
  );
});
