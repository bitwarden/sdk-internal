import { randomBytes, randomUUID } from "node:crypto";

import { LoginMethod, LOGIN_REQUEST } from "../../client-emulator/client-emulator";
import { SETTINGS } from "../../client-emulator/local-state";
import { testHarness, type TestHarness } from "../../test-harness";
import { rejection } from "../utils";
import {
  deleteAccount,
  registerWithPassword,
  type RegisteredAccount,
} from "./password-registration";

import { isPasswordLoginError } from "@bitwarden/sdk-internal";

/** Registration and deletion each derive a master key, and a test logs in more than once. */
const TIMEOUT = 60_000;

/**
 * Registration with a master password: the SDK makes the account's keys on the device, and the
 * account is usable at once.
 */
describe("password registration", () => {
  let harness: TestHarness;
  let account: RegisteredAccount;

  beforeEach(() => {
    harness = testHarness();
    account = {
      email: `sdk-it-${randomUUID()}@example.com`,
      password: randomBytes(24).toString("base64url"),
    };
  });

  afterEach(() => harness.restore());

  it(
    "registers an account that logs in and unlocks through the SDK",
    async () => {
      // 1. Register an account, then log in and unlock with its password
      await registerWithPassword(SETTINGS, account);
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
    "deletes a registered account, after which it can no longer log in",
    async () => {
      // 1. Register an account, then delete it
      await registerWithPassword(SETTINGS, account);
      expect(await deleteAccount(SETTINGS, LOGIN_REQUEST, account)).toBe("deleted");

      // 2. Verify server state: the login is refused as an unknown account's would be
      const thrown = await rejection(
        harness.newClientEmulator().login(account.email, LoginMethod.Password, account.password),
        isPasswordLoginError,
      );
      expect(thrown.variant).toBe("InvalidUsernameOrPassword");

      // 3. Verify a second deletion finds no account
      expect(await deleteAccount(SETTINGS, LOGIN_REQUEST, account)).toBe("absent");
    },
    TIMEOUT,
  );
});
