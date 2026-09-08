import { Kdf, isChangeKdfError, type PasswordManagerClient } from "@bitwarden/sdk-internal";

import type { ClientEmulator } from "../../client-emulator/client-emulator";

import { testHarness, type TestHarness } from "../../test-harness";
import { MASTER_PASSWORD_ACCOUNT } from "../../vectors/accounts";
import { rejection, TEST_EMAIL, TEST_KDF_PARAMS, TEST_PASSWORD } from "../utils";

const NEW_PBKDF2: Kdf = { pBKDF2: { iterations: 700_000 } };
const NEW_ARGON2: Kdf = { argon2id: { iterations: 3, memory: 16, parallelism: 4 } };
const BELOW_MINIMUM: Kdf = { argon2id: { iterations: 1, memory: 16, parallelism: 1 } };

const TIMEOUT = 60_000;

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

      // 3. Verify server state is fine: Sync from new cliend and unlock
      const reloginClient = harness.newClientEmulator();
      await reloginClient.login(email);
      await reloginClient.unlock(TEST_PASSWORD);
      const reloginSdk = reloginClient.getPasswordManagerClient();

      // 4. Verify the server has the new KDF values
      expect(await client.bridge.get_kdf_config()).toEqual(kdf);

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
});
