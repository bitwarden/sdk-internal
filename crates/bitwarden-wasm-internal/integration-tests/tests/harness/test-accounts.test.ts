import { LoginMethod } from "../../client-emulator/client-emulator";
import { testHarness, type TestHarness } from "../../test-harness";

const TIMEOUT = 60_000;

/**
 * The accounts a test creates for itself: registered as a client registers, usable at once, and
 * gone when the test ends.
 */
describe("test accounts", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  });

  afterEach(() => harness.dispose(), TIMEOUT);

  it(
    "creates an account that logs in, unlocks and syncs through the SDK",
    async () => {
      const account = await harness.accounts.create();

      const client = harness.newClientEmulator();
      await client.login(account.email, LoginMethod.Password, account.password);
      await client.unlock(account.password);

      expect(client.local.account.email).toBe(account.email);
      expect(
        await client.getPasswordManagerClient().crypto().get_user_encryption_key(),
      ).toBeTruthy();
    },
    TIMEOUT,
  );

  it(
    "gives each account its own address and password",
    async () => {
      const first = await harness.accounts.create();
      const second = await harness.accounts.create();

      expect(second.email).not.toBe(first.email);
      expect(second.password).not.toBe(first.password);
    },
    TIMEOUT,
  );

  it(
    "deletes its accounts, after which they can no longer log in",
    async () => {
      const account = await harness.accounts.create();

      await harness.accounts.deleteAll();

      await expect(
        harness.newClientEmulator().login(account.email, LoginMethod.Password, account.password),
      ).rejects.toBeDefined();
    },
    TIMEOUT,
  );
});
