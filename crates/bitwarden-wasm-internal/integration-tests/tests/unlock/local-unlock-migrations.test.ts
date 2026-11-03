import { LoginMethod } from "../../client-emulator/client-emulator";
import { UnlockMigrations } from "../../client-emulator/local-state";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import { TEST_PIN } from "../utils";

const TIMEOUT = 120_000; // KDF + wasm is slow

/**
 * A browser extension's background and each open popup unlock at the same time. Popups disable
 * local unlock migrations, so only the background reseals the ephemeral PIN envelope.
 *
 * ```
 * set PIN ─► restart ─► popup unlock ─────► background unlock
 *            (drops      (envelope stays     (envelope resealed)
 *            envelope)    missing)
 * ```
 */
describe("local unlock migrations", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  testVectors.users.withMasterPassword().each(
    "$name leaves the ephemeral PIN envelope to the client that runs migrations",
    async (vector) => {
      const password = vector.account.password;
      const seeded = harness.server.seedUserTestVector(vector);
      const client = harness.newClientEmulator();
      await client.login(seeded.email, LoginMethod.Password, password);
      await client.unlock(password);

      // 1. Enroll an AfterFirstUnlock PIN, then drop its envelope as reopening the app does
      await client
        .getPasswordManagerClient()
        .user_crypto_management()
        .pin_settings()
        .set_pin(TEST_PIN, "AfterFirstUnlock");
      await client.restart();

      // 2. Verify a client with migrations disabled leaves the envelope missing
      client.local.unlockMigrations = UnlockMigrations.Disabled;
      await client.unlock(password);
      expect(await client.bridge.get_ephemeral_pin_envelope()).toBeNull();

      // 3. Verify a client running migrations reseals it
      client.local.unlockMigrations = UnlockMigrations.Perform;
      await client.lock();
      await client.unlock(password);
      expect(await client.bridge.get_ephemeral_pin_envelope()).not.toBeNull();
    },
    TIMEOUT,
  );
});
