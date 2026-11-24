// Registration against a real server.
//
// Opt-in through `BW_LIVE_SERVER_URL`; skipped otherwise. Needs no fixed account: the test
// registers its own. See `live/config.ts` and the Readme.
//
// No counterpart in `e2e/kotlin` or `e2e/swift`: they have no live-server harness.

import { LoginMethod } from "../../client-emulator/client-emulator";
import { liveServer, requireLiveServer } from "../../live/config";
import { liveHarness, type TestHarness } from "../../test-harness";

/** Registration waits for an email, and every login and unlock runs a real KDF. */
const TIMEOUT = 300_000;

/** Absent configuration skips the suite rather than failing it: a default run must not need it. */
const describeLive = liveServer() === undefined ? describe.skip : describe;

describeLive("registration (live server)", () => {
  let harness: TestHarness;

  beforeEach(() => {
    const live = requireLiveServer();
    harness = liveHarness(live.settings, live.loginRequest);
  });

  afterEach(() => harness.restore());

  /**
   * A registered account logs in, holds a vault item, and a fresh login reads it back.
   *
   *   register ──▶ login ──▶ unlock ──▶ create item ──▶ fresh login ──▶ unlock ──▶ item decrypts
   */
  it(
    "registers an account that logs in and keeps its vault",
    async () => {
      // 1. Register, with the token from the verification email
      const account = await harness.registerAccount();

      // 2. Log in and unlock as a real client does
      const client = harness.newClientEmulator();
      await client.login(account.email, LoginMethod.Password, account.password);
      await client.unlock(account.password);

      // 3. Add a vault item through the SDK
      await client
        .getPasswordManagerClient()
        .vault()
        .ciphers()
        .create({
          organizationId: undefined,
          collectionIds: [],
          folderId: undefined,
          name: "sdk-internal registration test",
          notes: undefined,
          favorite: false,
          reprompt: 0,
          type: {
            login: {
              username: account.email,
              password: "a password the server has to keep",
              passwordRevisionDate: undefined,
              uris: undefined,
              totp: undefined,
              autofillOnPageLoad: undefined,
              fido2Credentials: undefined,
            },
          },
          fields: [],
        });

      // 4. Verify a client that logs in fresh decrypts the item, so the server holds keys that
      //    match the master password
      const relogin = harness.newClientEmulator();
      await relogin.login(account.email, LoginMethod.Password, account.password);
      await relogin.unlock(account.password);

      const { successes, failures } = await relogin
        .getPasswordManagerClient()
        .vault()
        .ciphers()
        .get_all();
      expect(failures).toEqual([]);
      expect(successes.map((cipher) => cipher.name)).toEqual(["sdk-internal registration test"]);
      expect(successes[0].login?.password).toBe("a password the server has to keep");
    },
    TIMEOUT,
  );
});
