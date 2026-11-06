import { isDeviceTrustError } from "@bitwarden/sdk-internal";

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
 *  fresh client: login, unlock with device key + server keys ─▶ vault decrypts
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

  testVectors.users.withMasterPassword().each(
    "$name unlocks with the device key after trusting",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const password = vector.account.password;
      const client = await loginAndChoose(seeded.email, password, "Trust");

      // 1. Trust the device
      const outcome = await client
        .getPasswordManagerClient()
        .device_trust()
        .trust_device_if_required();
      expect(outcome).toBe("Trusted");

      // 2. Verify local state: device key stored, choice consumed
      const deviceKey = await client.bridge.get_device_key();
      expect(deviceKey).not.toBeNull();
      expect(await client.bridge.get_should_trust_device()).toBeNull();

      // 3. Verify server state: a fresh client unlocks with the device key and the server's keys
      const device = deviceRow(seeded.email);
      expect(device?.encryptedUserKey).toBeTruthy();

      const relogin = harness.newClientEmulator();
      await relogin.login(seeded.email, LoginMethod.Password, password);
      await relogin.unlockWith({
        deviceKey: {
          device_key: deviceKey!,
          protected_device_private_key: asEncString(device!.encryptedPrivateKey!),
          device_protected_user_key: asUnsignedSharedKey(device!.encryptedUserKey!),
        },
      });
      await validateVault(relogin, seeded.seed);
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
});
