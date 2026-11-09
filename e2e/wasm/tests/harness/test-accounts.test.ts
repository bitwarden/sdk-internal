import { LoginMethod } from "../../client-emulator/client-emulator";
import type { AccountSource } from "../../live/accounts";
import { testHarness, type TestHarness } from "../../test-harness";
import { rejection } from "../utils";

import { isPasswordLoginError } from "@bitwarden/sdk-internal";

/** Registration and deletion each derive a master key, and a test logs in more than once. */
const TIMEOUT = 60_000;

const SOURCES: AccountSource[] = ["seeder", "register"];

/**
 * The accounts a test creates for itself: seeded or registered, usable at once, and gone when the
 * test ends. Tests behave the same whichever source made the account.
 */
describe.each(SOURCES)("test accounts from %s", (source) => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness(source);
  });

  afterEach(() => harness.dispose(), TIMEOUT);

  it(
    "creates an account that logs in, unlocks and syncs through the SDK",
    async () => {
      // 1. Create an account, then log in and unlock with its password
      const account = await harness.accounts.create();
      const client = harness.newClientEmulator();
      await client.login(account.email, LoginMethod.Password, account.password);
      await client.unlock(account.password);
      const userKey = await client.getPasswordManagerClient().crypto().get_user_encryption_key();

      // 2. Verify local state: lock, unlock, and the same user key comes back
      await client.lock();
      await client.unlock(account.password);
      expect(await client.getPasswordManagerClient().crypto().get_user_encryption_key()).toBe(
        userKey,
      );

      // 3. Verify server state: a fresh client logs in and unlocks to the same user key
      const relogin = harness.newClientEmulator();
      await relogin.login(account.email, LoginMethod.Password, account.password);
      await relogin.unlock(account.password);
      expect(await relogin.getPasswordManagerClient().crypto().get_user_encryption_key()).toBe(
        userKey,
      );
    },
    TIMEOUT,
  );

  it(
    "gives each account its own address and password",
    async () => {
      // 1. Create two accounts
      const first = await harness.accounts.create();
      const second = await harness.accounts.create();

      // 2. Verify they share neither address nor password
      expect(second.email).not.toBe(first.email);
      expect(second.password).not.toBe(first.password);
    },
    TIMEOUT,
  );

  it(
    "deletes its accounts, after which they can no longer log in",
    async () => {
      // 1. Create an account, then delete the test's accounts
      const account = await harness.accounts.create();
      await harness.accounts.deleteAll();

      // 2. Verify server state: the login is refused as an unknown account's would be
      const thrown = await rejection(
        harness.newClientEmulator().login(account.email, LoginMethod.Password, account.password),
        isPasswordLoginError,
      );
      expect(thrown.variant).toBe("InvalidUsernameOrPassword");
    },
    TIMEOUT,
  );
});

/** Deleting by address alone, which only registered accounts need: seeded ones go with their play. */
describe("registered test accounts", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness("register");
  });

  afterEach(() => harness.dispose(), TIMEOUT);

  it(
    "reports an account that doesn't exist as absent, so a sweep stops retrying it",
    async () => {
      // 1. Create an account, then delete the test's accounts
      const account = await harness.accounts.create();
      await harness.accounts.deleteAll();

      // 2. Verify a second deletion finds no account and says so
      expect(await harness.accounts.deleteByEmail(account.email)).toBe("absent");
    },
    TIMEOUT,
  );
});
