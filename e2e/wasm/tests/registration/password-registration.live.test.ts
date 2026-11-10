// Password registration against a real server.
//
// Opt-in through `BW_LIVE_SERVER_URL`; skipped otherwise. See `live/config.ts` and the README.

import { randomBytes, randomUUID } from "node:crypto";

import { LoginMethod } from "../../client-emulator/client-emulator";
import { liveConfig, requireLiveConfig, type LiveConfig } from "../../live/config";
import { liveHarness, type TestHarness } from "../../test-harness";
import {
  deleteAccount,
  registerWithPassword,
  type RegisteredAccount,
} from "./password-registration";

/** Registration, deletion and each login derive a master key over the network. */
const TIMEOUT = 120_000;

const config = liveConfig();

/** Absent configuration skips the suite rather than failing it: a default run must not need it. */
const describeLive = config === undefined ? describe.skip : describe;

describeLive("password registration (live server)", () => {
  let live: LiveConfig;
  let harness: TestHarness;
  let account: RegisteredAccount;

  beforeEach(() => {
    live = requireLiveConfig();
    harness = liveHarness(live);
    account = {
      email: `sdk-it-${randomUUID()}@${live.emailDomain}`,
      password: randomBytes(24).toString("base64url"),
    };
  });

  // A registered account is not part of a play, so the test deletes it itself.
  afterEach(async () => {
    try {
      await deleteAccount(live.settings, live.loginRequest, account);
    } finally {
      harness.restore();
    }
  }, TIMEOUT);

  it(
    "registers an account that logs in and unlocks through the SDK",
    async () => {
      // 1. Register an account, then log in and unlock with its password
      await registerWithPassword(live.settings, account, live.seeder);
      const client = harness.newClientEmulator();
      await client.login(account.email, LoginMethod.Password, account.password);
      await client.unlock(account.password);
      const userKey = await client.getPasswordManagerClient().crypto().get_user_encryption_key();

      // 2. Verify server state: a fresh client logs in and unlocks to the same user key
      const relogin = harness.newClientEmulator();
      await relogin.login(account.email, LoginMethod.Password, account.password);
      await relogin.unlock(account.password);
      expect(await relogin.getPasswordManagerClient().crypto().get_user_encryption_key()).toBe(
        userKey,
      );
    },
    TIMEOUT,
  );
});
