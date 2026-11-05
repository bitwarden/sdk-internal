import type { WebAuthnPrfUnlockOption } from "@bitwarden/sdk-internal";

import { LoginMethod } from "../../client-emulator/client-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import { asEncString, asUnsignedSharedKey } from "../type-assertion-helpers";
import { rotateByPassword as rotate } from "../user-crypto-management/rotate-helpers";

const TIMEOUT = 120_000;

const V1_VECTOR = testVectors.users.withMasterPassword().get("v1-pbkdf2-min-iterations");
const V2_VECTOR = testVectors.users.withMasterPassword().get("v2-pbkdf2-blob");

/**
 * A passkey registered for PRF unlock. The handler stores it and never unwraps it, so shape-valid
 * values suffice: a PRF-key-wrapped private key, and the user key encapsulated to its public key.
 */
const PRF_OPTION: WebAuthnPrfUnlockOption = {
  encryptedPrivateKey: asEncString(
    "2.fkvl0+sL1lwtiOn1eewsvQ==|dT0TynLl8YERZ8x7dxC+DQ==|cWhiRSYHOi/AA2LiV/JBJWbO9C7pbUpOM6TMAcV47hE=",
  ),
  encryptedUserKey: asUnsignedSharedKey(
    "4.DMD1D5r6BsDDd7C/FE1eZbMCKrmryvAsCKj6+bO54gJNUxisOI7SDcpPLRXf+JdhqY15pT+wimQ5cD9C+6OQ6s71LFQHewXPU29l9Pa1JxGeiKqp37KLYf+1IS6UB2K3ANN35C52ZUHh2TlzIS5RuntxnpCw7APbcfpcnmIdLPJBtuj/xbFd6eBwnI3GSe5qdS6/Ixdd0dgsZcpz3gHJBKmIlSo0YN60SweDq3kTJwox9xSqdCueIDg5U4khc7RhjYx8b33HXaNJj3DwgIH8iLj+lqpDekogr630OhHG3XRpvl4QzYO45bmHb8wAh67Dj70nsZcVg6bAEFHdSFohww==",
  ),
  credentialId: "test-credential-id",
  transports: ["internal", "hybrid"],
};

/**
 * The crypto sync handler mirrors what the server reports into client state on every sync. Each
 * test changes what the server holds, syncs, and reads client state back.
 */
describe("crypto sync handler", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  testVectors.users.each(
    "$name stores the server's key material on login",
    async (vector) => {
      // 1. Log in, which syncs
      const seeded = harness.server.seedUserTestVector(vector);
      const device = await harness.newUnlockedClient(seeded);

      // 2. Verify client state holds what the server does
      const stored = harness.server.getUser(seeded.email);
      expect(await device.bridge.get_account_cryptographic_state()).toEqual(
        stored.accountCryptographicState,
      );
      expect(await device.bridge.get_kdf_config()).toEqual(stored.kdf);
      expect((await device.bridge.get_masterpassword_unlock_data())?.masterKeyWrappedUserKey).toBe(
        stored.masterPasswordUnlock?.masterKeyWrappedUserKey,
      );
    },
    TIMEOUT,
  );

  /**
   * An absent key id means the server has none recorded for this user key, so a previously stored
   * one no longer describes anything.
   */
  it(
    "clears the stored user key id when the server reports none",
    async () => {
      // 1. A device that holds a key id, which a rotation records
      const { email, vector } = harness.server.seedUserTestVector(V2_VECTOR);
      const device = harness.newClientEmulator();
      await device.login(email, LoginMethod.Password, vector.account.password);
      await device.unlock(vector.account.password);
      await rotate(device.getPasswordManagerClient(), vector.account.password, "Skip");
      await device.sync();
      expect(await device.bridge.get_user_key_id()).toBeTruthy();

      // 2. The server stops reporting one, and the device syncs
      delete harness.server.getUser(email).userKeyId;
      await device.sync();

      // 3. Verify the stored key id is gone
      expect(await device.bridge.get_user_key_id()).toBeFalsy();
    },
    TIMEOUT,
  );

  /** No PRF-capable passkeys are left on the account, reported as an absent or an empty list. */
  for (const [label, remaining] of [
    ["none", undefined],
    ["an empty list", []],
  ] as const) {
    it(
      `stores webauthn prf options, and clears them when the server reports ${label}`,
      async () => {
        // 1. The account registers a passkey, and a device syncs it down
        const seeded = harness.server.seedUserTestVector(V2_VECTOR);
        harness.server.getUser(seeded.email).webAuthnPrfOptions = [PRF_OPTION];
        const device = await harness.newUnlockedClient(seeded);

        // 2. Verify the device stores it
        expect(await device.bridge.get_webauthn_prf_unlock_data()).toEqual({
          options: [PRF_OPTION],
        });

        // 3. The passkey is removed, and the device syncs
        harness.server.getUser(seeded.email).webAuthnPrfOptions = remaining && [...remaining];
        await device.sync();

        // 4. Verify the device no longer holds it
        expect(await device.bridge.get_webauthn_prf_unlock_data()).toBeFalsy();
      },
      TIMEOUT,
    );
  }

  /**
   * An upgrade token is outstanding from a V1 to V2 rotation until the next rotation clears it.
   *
   *   device ──rotate(V1→V2)─▶ sync (token stored) ─▶ rotate(V2→V2) ─▶ sync (token gone)
   */
  it(
    "clears a stored upgrade token when the server reports none",
    async () => {
      // 1. A device that upgraded the account, and holds the token
      const { email, vector } = harness.server.seedUserTestVector(V1_VECTOR);
      const device = harness.newClientEmulator();
      await device.login(email, LoginMethod.Password, vector.account.password);
      await device.unlock(vector.account.password);
      await rotate(device.getPasswordManagerClient(), vector.account.password, "CreateIfNeeded");
      await device.sync();
      expect(await device.bridge.get_v2_upgrade_token()).toBeTruthy();

      // 2. A second rotation clears the token on the server, and the device syncs
      await rotate(device.getPasswordManagerClient(), vector.account.password, "Skip");
      await device.sync();

      // 3. Verify the stored token is gone
      expect(await device.bridge.get_v2_upgrade_token()).toBeFalsy();
    },
    TIMEOUT,
  );

  /** An absent unlock method means the account no longer has a master password. */
  it(
    "clears stored master password unlock data when the server reports none",
    async () => {
      // 1. A device on an account with a master password
      const seeded = harness.server.seedUserTestVector(V2_VECTOR);
      const device = await harness.newUnlockedClient(seeded);

      // 2. The account drops its master password, and the device syncs
      harness.server.getUser(seeded.email).masterPasswordUnlock = null;
      await device.sync();

      // 3. Verify the stored unlock data is gone
      expect(await device.bridge.get_masterpassword_unlock_data()).toBeFalsy();
    },
    TIMEOUT,
  );
});
