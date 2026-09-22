// Password login against the identity service emulator.
//
// The two calls are separate on purpose: prelogin tells a client how to derive its master key, and
// `login_via_password` derives the authentication hash against *that* KDF rather than any stored
// one. A client that reused the wrong KDF would still produce a hash, just not the right one.

import { SETTINGS } from "../../client-emulator/local-state";
import { testHarness, type TestHarness } from "../../test-harness";
import { makePasswordManagerClient, makeStateBridge } from "../utils";
import {
  loadUserVectors,
  toSeedAccount,
  unlockMethodName,
  userVector,
  type UserVector,
} from "../../vectors/load";
import { testVectors } from "../../vectors/test-vectors";

import type { LoginClient, LoginRequest, PasswordPreloginResponse } from "@bitwarden/sdk-internal";

/** A real KDF derivation per login, and one of the accounts uses argon2id. */
const TIMEOUT = 120_000;

const LOGIN_REQUEST: LoginRequest = {
  clientId: "web",
  device: {
    deviceType: "SDK",
    deviceIdentifier: "integration-test-device",
    deviceName: "Integration Tests",
    devicePushToken: undefined,
  },
};

/** Only a master-password account can log in by password. */
const hasMasterPassword = (vector: UserVector): boolean =>
  vector.unlockMethods.some((method) => unlockMethodName(method) === "masterPasswordUnlock");

/** The account the failure cases run against, where the vector under test does not matter. */
const PASSWORD_VECTOR = userVector(loadUserVectors(), "v1-pbkdf2-password");

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

  async function login(
    client: LoginClient,
    email: string,
    password: string,
    prelogin: PasswordPreloginResponse,
  ) {
    return await client.login_via_password({
      loginRequest: LOGIN_REQUEST,
      email,
      password,
      preloginResponse: prelogin,
    });
  }

  testVectors.eachUser()(
    "%s learns its KDF from prelogin",
    async (_name, vector) => {
      if (!hasMasterPassword(vector)) {
        return;
      }

      harness.server.seedUser(toSeedAccount(vector));

      const prelogin = await loginClient().get_password_prelogin(vector.account.email);

      expect(prelogin.kdf).toEqual(vector.account.kdf);
      expect(prelogin.salt).toEqual(vector.account.email);
    },
    TIMEOUT,
  );

  testVectors.eachUser()(
    "%s authenticates and is handed unlock data that opens its vault",
    async (_name, vector) => {
      if (!hasMasterPassword(vector)) {
        return;
      }

      harness.server.seedUser(toSeedAccount(vector));
      const client = loginClient();

      const prelogin = await client.get_password_prelogin(vector.account.email);
      const response = await login(client, vector.account.email, vector.account.password, prelogin);

      // The account is now reachable with the issued token, and the unlock data it came back with
      // is the account's own.
      const authenticated = response.Authenticated;
      expect(authenticated.accessToken).toEqual(vector.account.userId);

      const unlock = authenticated.userDecryptionOptions.masterPasswordUnlock;
      expect(unlock?.salt).toEqual(vector.account.email);
      expect(unlock?.kdf).toEqual(vector.account.kdf);
    },
    TIMEOUT,
  );

  it(
    "refuses a wrong password",
    async () => {
      const vector = PASSWORD_VECTOR;
      harness.server.seedUser(toSeedAccount(vector));
      const client = loginClient();

      const prelogin = await client.get_password_prelogin(vector.account.email);

      await expect(
        login(client, vector.account.email, "not-the-password", prelogin),
      ).rejects.toBeDefined();
    },
    TIMEOUT,
  );

  it(
    "refuses to prelogin an account the server does not have",
    async () => {
      await expect(
        loginClient().get_password_prelogin("nobody@test.bitwarden.com"),
      ).rejects.toBeDefined();
    },
    TIMEOUT,
  );
});
