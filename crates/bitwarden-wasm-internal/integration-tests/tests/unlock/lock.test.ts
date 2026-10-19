import { validateVault } from "../../client-emulator/validate";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";

const TIMEOUT = 120_000;

const VECTOR = testVectors.users.withMasterPassword().get("v2-pbkdf2-blob");

describe("lock", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /**
   * A long-lived client locks in place and is unlocked again, without being replaced.
   *
   *   client  ──unlock(P)─▶ reads ─▶ lock() ─▶ reads fail ─▶ unlock(P) ─▶ reads
   *           └──────────────── one PasswordManagerClient throughout ──────────┘
   */
  it(
    "locks a client in place and unlocks the same instance again",
    async () => {
      const seeded = harness.server.seedUserTestVector(VECTOR);
      const client = harness.newClientEmulator();
      await client.login(seeded.email);
      await client.unlock(VECTOR.account.password);

      const sdk = client.getPasswordManagerClient();
      const userKey = await sdk.crypto().get_user_encryption_key();

      // 1. Verify the unlocked client reads the vault, and its state holds the user key
      await validateVault(client, seeded.seed);
      expect(await client.bridge.get_user_key()).toBe(userKey);

      // 2. Lock in place
      await sdk.unlock().lock();

      // 3. Verify the user key is gone from state, and the vault no longer decrypts
      expect(await client.bridge.get_user_key()).toBeNull();
      await expect(validateVault(client, seeded.seed)).rejects.toThrow();

      // 4. Unlock the same instance again
      await client.unlockInPlace(VECTOR.account.password);
      expect(client.getPasswordManagerClient()).toBe(sdk);

      // 5. Verify it reads the vault again, and its state holds the same user key
      await validateVault(client, seeded.seed);
      expect(await client.bridge.get_user_key()).toBe(userKey);
      expect(await sdk.crypto().get_user_encryption_key()).toBe(userKey);
    },
    TIMEOUT,
  );
});
