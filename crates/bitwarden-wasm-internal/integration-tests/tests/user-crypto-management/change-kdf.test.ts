import { Kdf, isChangeKdfError } from "@bitwarden/sdk-internal";

import { validateVault } from "../../client-emulator/validate";
import { testHarness, type TestHarness } from "../../test-harness";
import { loadUserVectors, unlockMethodName, userVector, type UserVector } from "../../vectors/load";
import { testVectors } from "../../vectors/test-vectors";
import { rejection } from "../utils";

const NEW_PBKDF2: Kdf = { pBKDF2: { iterations: 700_000 } };
const NEW_ARGON2: Kdf = { argon2id: { iterations: 3, memory: 16, parallelism: 4 } };
const BELOW_MINIMUM: Kdf = { argon2id: { iterations: 1, memory: 16, parallelism: 1 } };

/** Only a master-password account has a KDF to change. */
const hasMasterPassword = (vector: UserVector): boolean =>
  vector.unlockMethods.some((method) => unlockMethodName(method) === "masterPasswordUnlock");

/** The account the failure cases run against, where the vector under test does not matter. */
const V1_VECTOR = userVector(loadUserVectors(), "v1-pbkdf2-min-iterations");

const TIMEOUT = 120_000;

describe("change kdf", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  describe.each([
    { name: "pbkdf2", kdf: NEW_PBKDF2 },
    { name: "argon2id", kdf: NEW_ARGON2 },
  ])("change kdf to $name", ({ kdf }) => {
    testVectors.eachUser()(
      "%s keeps its user key and its vault",
      async (_name, vector) => {
        if (!hasMasterPassword(vector)) {
          return;
        }

        const seeded = harness.server.seedUserTestVector(vector);
        const client = harness.newClientEmulator();
        await client.login(seeded.email);
        await client.unlock(vector.account.password);

        const passwordManagerClient = client.getPasswordManagerClient();
        const password = vector.account.password;
        const userKey = await passwordManagerClient.crypto().get_user_encryption_key();

        // 1. Change the KDF
        await passwordManagerClient.user_crypto_management().change_kdf(password, kdf);

        // 2. Verify local state is fine: Lock & unlock
        await client.lock();
        await client.unlock(password);
        const lockUnlockSdk = client.getPasswordManagerClient();
        expect(await client.bridge.get_kdf_config()).toEqual(kdf);

        // 3. Verify server state is fine: Sync from new client and unlock
        const reloginClient = harness.newClientEmulator();
        await reloginClient.login(seeded.email);
        await reloginClient.unlock(password);
        const reloginSdk = reloginClient.getPasswordManagerClient();

        // 4. Verify the new KDF values reached the new client through the sync
        expect(await reloginClient.bridge.get_kdf_config()).toEqual(kdf);

        // 5. Verify the encryption key has not changed
        expect(await lockUnlockSdk.crypto().get_user_encryption_key()).toBe(userKey);
        expect(await reloginSdk.crypto().get_user_encryption_key()).toBe(userKey);

        // 6. Verify the vault the returning client synced still decrypts to what the vector
        //    records. That client unlocked from its own synced state, not the vector's: the change
        //    rewrote the unlock data, and opening the recorded copy would prove nothing about what
        //    was written.
        await validateVault(reloginClient, seeded.seed);
      },
      TIMEOUT,
    );
  });

  /**
   * A second session, unlocked before the change, picks the new KDF up from a sync and unlocks
   * with the same password. A KDF change re-wraps the user key without replacing it, so nothing in
   * the vault had to be re-encrypted.
   *
   *   device 1  ──unlock(P)──┬── change_kdf ──────────────────────────▶ reads
   *                          │        │
   *   server    ─────────────┴────────┴── new unlock data, same user key
   *                                   │
   *   device 2  ──unlock(P)───────────┴── sync ─▶ lock ─▶ unlock(P) ──▶ reads
   */
  it(
    "second device can read the vault after the first device changes the kdf",
    async () => {
      // 1. Two unlocked clients, and a kdf change by the first
      const seeded = harness.server.seedUserTestVector(V1_VECTOR);
      const client = harness.newClientEmulator();
      await client.login(seeded.email);
      await client.unlock(V1_VECTOR.account.password);

      const second = harness.newClientEmulator();
      await second.login(seeded.email);
      await second.unlock(V1_VECTOR.account.password);

      await client
        .getPasswordManagerClient()
        .user_crypto_management()
        .change_kdf(V1_VECTOR.account.password, NEW_PBKDF2);
      // Sync is triggered by a push notification usually. In this case we do it manually
      // because push notifications are not implemented in the emulator.
      await second.sync(seeded.email);
      expect(await second.bridge.get_kdf_config()).toEqual(NEW_PBKDF2);

      // 2. The second session locks and unlocks, picking up the new kdf and unlock data the sync
      //    brought down
      await second.lock();
      await second.unlock(V1_VECTOR.account.password);

      // 3. Verify the vault reads, with the plaintext unchanged
      await validateVault(second, seeded.seed);
    },
    TIMEOUT,
  );

  describe("failures", () => {
    it(
      "changes nothing when the new KDF is below the allowed minimum",
      async () => {
        const seeded = harness.server.seedUserTestVector(V1_VECTOR);
        const client = harness.newClientEmulator();
        await client.login(seeded.email);
        await client.unlock(V1_VECTOR.account.password);

        // 1. Change the KDF to settings the SDK must refuse before asking the server
        const error = await rejection(
          client
            .getPasswordManagerClient()
            .user_crypto_management()
            .change_kdf(V1_VECTOR.account.password, BELOW_MINIMUM),
          isChangeKdfError,
        );

        // 2. Verify the SDK refused it
        expect(error.variant).toBe("MasterPassword");

        // 3. Verify neither side moved
        expect(harness.server.getUser(seeded.email).kdf).toEqual(V1_VECTOR.account.kdf);
        expect(await client.bridge.get_kdf_config()).toEqual(V1_VECTOR.account.kdf);
      },
      TIMEOUT,
    );
  });
});
