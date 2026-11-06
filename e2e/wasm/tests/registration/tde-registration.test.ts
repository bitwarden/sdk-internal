import { isRegistrationError, type PublicKey } from "@bitwarden/sdk-internal";

import { LoginMethod, type ClientEmulator } from "../../client-emulator/client-emulator";
import { DEVICE_IDENTIFIER } from "../../client-emulator/local-state";
import type { DeviceEntity } from "../../server-emulator/entities";
import { testHarness, type TestHarness } from "../../test-harness";
import { TEST_ORG_PUBLIC_KEY, TEST_ORGANIZATION_ID } from "../org-fixtures";
import { asB64, asEncString, asUnsignedSharedKey, asUserId } from "../type-assertion-helpers";
import { rejection } from "../utils";

const EMAIL = "tde-jit@example.com";

const TIMEOUT = 120_000;

/**
 * Registering a just-in-time provisioned trusted device user.
 *
 * ```
 *  client                                  server
 *  ──────                                  ──────
 *  SSO login (registers device) ─────────▶ keyless account, device row
 *  post_keys_for_tde_registration
 *    ├─ POST /accounts/keys ─────────────▶ account now has keys
 *    ├─ PUT …/reset-password-enrollment ─▶ account recovery key
 *    ├─ account state ─▶ bridge, unlock
 *    └─ trust (if chosen) ───────────────▶ PUT /devices/:id/keys
 *
 *  later: login, lock, unlock with trustedDevice(server keys) ─▶ same user key
 * ```
 */
describe("tde registration", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  function seedOrganization(): void {
    harness.server.seedOrganization({
      organizationId: TEST_ORGANIZATION_ID,
      name: "TDE organization",
      publicKey: TEST_ORG_PUBLIC_KEY as unknown as PublicKey,
      members: [],
    });
  }

  function deviceRow(email: string): DeviceEntity | undefined {
    const user = harness.server.getUser(email);
    const [device] = harness.server.db.devices.filter(
      (candidate) => candidate.userId === user.userId && candidate.identifier === DEVICE_IDENTIFIER,
    );

    return device;
  }

  async function register(trust: "Trust" | "DontTrust"): Promise<ClientEmulator> {
    const account = harness.server.seedPendingAccount(EMAIL);
    const client = harness.newClientEmulator();

    await client.loginForRegistration(EMAIL).post_keys_for_tde_registration({
      org_id: TEST_ORGANIZATION_ID,
      org_public_key: asB64(TEST_ORG_PUBLIC_KEY),
      user_id: asUserId(account.userId),
      email: EMAIL,
      trust,
    });

    return client;
  }

  it(
    "registers, unlocks and trusts the device",
    async () => {
      seedOrganization();

      // 1. Register
      const client = await register("Trust");

      // 2. Verify local state: unlocked, account state and device key persisted
      const userKey = await client.getPasswordManagerClient().crypto().get_user_encryption_key();
      expect(await client.bridge.get_account_cryptographic_state()).not.toBeNull();
      expect(await client.bridge.get_device_key()).not.toBeNull();

      // 3. Verify server state: keys, account recovery and trusted device keys stored
      const user = harness.server.getUser(EMAIL);
      expect("V2" in user.accountCryptographicState).toBe(true);
      expect(
        harness.server.db.accountRecoveryEnrollments.filter(
          (enrollment) => enrollment.userId === user.userId,
        ),
      ).toHaveLength(1);
      const device = deviceRow(EMAIL);
      expect(device?.encryptedUserKey).toBeTruthy();

      // 4. Verify both sides together: log in again, lock, unlock with only the server's keys
      await client.login(EMAIL, LoginMethod.Unimplemented);
      await client.lock();
      await client.unlockWith({
        trustedDevice: {
          option: {
            encryptedPrivateKey: asEncString(device!.encryptedPrivateKey!),
            encryptedUserKey: asUnsignedSharedKey(device!.encryptedUserKey!),
          },
        },
      });
      expect(await client.getPasswordManagerClient().crypto().get_user_encryption_key()).toBe(
        userKey,
      );
    },
    TIMEOUT,
  );

  it(
    "registers and unlocks without trusting the device when declined",
    async () => {
      seedOrganization();

      // 1. Register
      const client = await register("DontTrust");

      // 2. Verify unlocked, but neither side holds device trust
      await client.getPasswordManagerClient().crypto().get_user_encryption_key();
      expect(await client.bridge.get_device_key()).toBeNull();
      expect(deviceRow(EMAIL)?.encryptedUserKey).toBeNull();
    },
    TIMEOUT,
  );

  it(
    "stays locked when account recovery enrollment fails",
    async () => {
      // No organization: the enrollment answers 404 after the keys were posted.
      const account = harness.server.seedPendingAccount(EMAIL);
      const client = harness.newClientEmulator();
      const registration = client.loginForRegistration(EMAIL);

      // 1. Act
      const error = await rejection(
        registration.post_keys_for_tde_registration({
          org_id: TEST_ORGANIZATION_ID,
          org_public_key: asB64(TEST_ORG_PUBLIC_KEY),
          user_id: asUserId(account.userId),
          email: EMAIL,
          trust: "Trust",
        }),
        isRegistrationError,
      );

      // 2. Verify nothing was persisted or unlocked locally, and no device trusted
      expect(error.variant).toBe("Api");
      await expect(
        client.getPasswordManagerClient().crypto().get_user_encryption_key(),
      ).rejects.toBeDefined();
      expect(await client.bridge.get_account_cryptographic_state()).toBeFalsy();
      expect(await client.bridge.get_device_key()).toBeNull();
      expect(deviceRow(EMAIL)?.encryptedUserKey).toBeNull();
    },
    TIMEOUT,
  );
});
