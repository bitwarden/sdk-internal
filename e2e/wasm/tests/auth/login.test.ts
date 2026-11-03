import { SETTINGS } from "../../client-emulator/local-state";
import { testHarness, type TestHarness } from "../../test-harness";
import { makePasswordManagerClient, makeStateBridge, rejection } from "../utils";
import { toSeedAccount } from "../../vectors/load";
import { testVectors } from "../../vectors/test-vectors";

import { isPasswordLoginError, type LoginClient, type LoginRequest } from "@bitwarden/sdk-internal";

/** A real KDF derivation per login, and one of the accounts uses argon2id. */
const TIMEOUT = 120_000;

const HTTP_OK = 200;

const LOGIN_REQUEST: LoginRequest = {
  clientId: "web",
  device: {
    deviceType: "SDK",
    deviceIdentifier: "integration-test-device",
    deviceName: "Integration Tests",
    devicePushToken: undefined,
  },
};

describe("login via password", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  });

  afterEach(() => harness.restore());

  /** A login client, which is unauthenticated and so carries no account of its own. */
  function loginClient(): LoginClient {
    return makePasswordManagerClient(makeStateBridge(), SETTINGS).auth().login();
  }

  testVectors.users.withMasterPassword().each(
    "$name learns its KDF from prelogin",
    async (vector) => {
      harness.server.seedUser(toSeedAccount(vector));

      const prelogin = await loginClient().get_password_prelogin(vector.account.email);

      expect(prelogin.kdf).toEqual(vector.account.kdf);
      expect(prelogin.salt).toEqual(vector.account.email);
    },
    TIMEOUT,
  );

  testVectors.users.withMasterPassword().each(
    "$name authenticates and is handed unlock data that opens its vault",
    async (vector) => {
      harness.server.seedUser(toSeedAccount(vector));
      const client = loginClient();

      const prelogin = await client.get_password_prelogin(vector.account.email);
      const response = await client.login_via_password({
        loginRequest: LOGIN_REQUEST,
        email: vector.account.email,
        password: vector.account.password,
        preloginResponse: prelogin,
      });

      // The account is now reachable with the issued token, and the unlock data it came back with
      // is the account's own. The test treats the token as opaque: it checks that the token
      // authenticates the account, not what the token holds.
      const authenticated = response.Authenticated;
      const synced = await fetch(`${SETTINGS.apiUrl}/sync`, {
        headers: { Authorization: `Bearer ${authenticated.accessToken}` },
      });
      expect(synced.status).toBe(HTTP_OK);
      expect((await synced.json()).profile.id).toEqual(vector.account.userId);

      const unlock = authenticated.userDecryptionOptions.masterPasswordUnlock;
      expect(unlock?.kdf).toEqual(vector.account.kdf);
    },
    TIMEOUT,
  );

  it(
    "refuses a wrong password",
    async () => {
      const vector = testVectors.users.withMasterPassword().get("v1-pbkdf2-password");
      harness.server.seedUser(toSeedAccount(vector));
      const client = loginClient();

      const prelogin = await client.get_password_prelogin(vector.account.email);

      await expect(
        client.login_via_password({
          loginRequest: LOGIN_REQUEST,
          email: vector.account.email,
          password: "not-the-password",
          preloginResponse: prelogin,
        }),
      ).rejects.toBeDefined();
    },
    TIMEOUT,
  );

  /**
   * Prelogin can't tell which addresses have accounts: the server answers an unknown one with a
   * default KDF, and only the login itself is refused, as a wrong password would be.
   */
  it(
    "answers prelogin for an account the server does not have, then refuses the login",
    async () => {
      const email = "nobody@test.bitwarden.com";
      const client = loginClient();

      const prelogin = await client.get_password_prelogin(email);
      expect(prelogin.kdf).toEqual({ pBKDF2: { iterations: 600_000 } });

      const thrown = await rejection(
        client.login_via_password({
          loginRequest: LOGIN_REQUEST,
          email,
          password: "not a password anyone has",
          preloginResponse: prelogin,
        }),
        isPasswordLoginError,
      );
      expect(thrown.variant).toBe("InvalidUsernameOrPassword");
    },
    TIMEOUT,
  );
});
