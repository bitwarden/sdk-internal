import { SymmetricKey } from "@bitwarden/sdk-internal";

import type { SeededTestVector } from "../../server-emulator/server-emulator";
import { IGNORED_FIELDS, validateVault } from "../../client-emulator/validate";
import type { ClientEmulator } from "../../client-emulator/client-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";

const TIMEOUT = 120_000;

const V1_VECTOR = testVectors.users.withMasterPassword().get("v1-pbkdf2-min-iterations");

const ROTATED_FIELDS = [...IGNORED_FIELDS, "key"];

/** A V1 user key is AES-256-CBC-HMAC: 32 bytes of encryption key plus 32 of MAC key. */
const V1_USER_KEY_BYTES = 64;

/** A V2 user key is a COSE key, which carries more than the raw 32 bytes of key material. */
const isV2UserKey = (key: SymmetricKey | null) =>
  key !== null && Buffer.from(key as unknown as string, "base64").length > V1_USER_KEY_BYTES;

/**
 * Another device upgrades a V1 account to V2. A device that picks the upgrade up through sync has
 * to persist the V2 user key, otherwise its next rebuild reads the stale V1 key back out of state
 * and is prompted to rotate again, which signs every device out.
 *
 *   device A ──unlock(K1)──────────────────────┬── sync ─▶ state holds K2?
 *                                              │
 *   device B ──unlock(K1)──rotate──▶ K2 ───────┘
 */
describe("v2 upgrade from another device", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /** Device A unlocked on V1, then device B upgrades the account. Device A has not synced. */
  async function upgradeElsewhere(): Promise<{ device: ClientEmulator; seeded: SeededTestVector }> {
    const seeded = harness.server.seedUserTestVector(V1_VECTOR);

    const device = harness.newClientEmulator();
    await device.login(seeded.email);
    await device.unlock(V1_VECTOR.account.password);

    const rotatingDevice = harness.newClientEmulator();
    await rotatingDevice.login(seeded.email);
    await rotatingDevice.unlock(V1_VECTOR.account.password);
    await rotatingDevice
      .getPasswordManagerClient()
      .user_crypto_management()
      .rotate_user_keys({
        key_rotation_method: { Password: { password: V1_VECTOR.account.password } },
        trusted_emergency_access_public_keys: [],
        trusted_organization_public_keys: [],
        upgrade_token_action: "CreateIfNeeded",
      });

    return { device, seeded };
  }

  it(
    "persists the V2 user key when an unlocked client syncs the upgrade",
    async () => {
      const { device, seeded } = await upgradeElsewhere();
      expect(isV2UserKey(await device.bridge.get_user_key())).toBe(false);

      await device.sync(seeded.email, "Unlocked");

      expect(isV2UserKey(await device.bridge.get_user_key())).toBe(true);
      await validateVault(device, seeded.seed, ROTATED_FIELDS);
    },
    TIMEOUT,
  );

  it(
    "persists the V2 user key when a client rebuilds from state after the sync",
    async () => {
      const { device, seeded } = await upgradeElsewhere();
      await device.sync(seeded.email);
      expect(isV2UserKey(await device.bridge.get_user_key())).toBe(false);

      // The sync-driven rebuild: the V1 key in state is upgraded in memory through the token
      await device.unlockWith({ clientManagedState: {} });

      expect(isV2UserKey(await device.bridge.get_user_key())).toBe(true);
      await validateVault(device, seeded.seed, ROTATED_FIELDS);
    },
    TIMEOUT,
  );

  it(
    "persists the V2 user key when reinit_user_crypto applies the upgrade",
    async () => {
      const { device, seeded } = await upgradeElsewhere();
      await device.sync(seeded.email);
      expect(isV2UserKey(await device.bridge.get_user_key())).toBe(false);

      await device.reinit();

      expect(isV2UserKey(await device.bridge.get_user_key())).toBe(true);
      await validateVault(device, seeded.seed, ROTATED_FIELDS);
    },
    TIMEOUT,
  );
});
