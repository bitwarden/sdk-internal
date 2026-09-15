// Password login against the identity service emulator.
//
// The two calls are separate on purpose: prelogin tells a client how to derive its master key, and
// `login_via_password` derives the authentication hash against *that* KDF rather than any stored
// one. A client that reused the wrong KDF would still produce a hash, just not the right one.

import { SETTINGS } from "../../client-emulator/local-state";
import { testHarness, type TestHarness } from "../../test-harness";
import { makePasswordManagerClient, makeStateBridge } from "../utils";
import { loadUserVectors, toSeedAccount, userVector, type UserVector } from "../../vectors/load";

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

/** One account per KDF, so a hash derived against the wrong one cannot pass both. */
const VECTORS = ["v1-pbkdf2-password", "v1-argon2id-password"];

describe("login via password", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  });

  afterEach(() => harness.restore());

  /** A login client, which is unauthenticated and so carries no account of its own. */
  function loginClient(): LoginClient {
    return makePasswordManagerClient(makeStateBridge()).auth().login(SETTINGS);
  }

  function seed(name: string): UserVector {
    const vector = userVector(loadUserVectors(), name);
    harness.server.seedUser(toSeedAccount(vector));

    return vector;
  }

  function login(
    client: LoginClient,
    vector: UserVector,
    prelogin: PasswordPreloginResponse,
    password = vector.account.password,
  ) {
    return client.login_via_password({
      loginRequest: LOGIN_REQUEST,
      email: vector.account.email,
      password,
      preloginResponse: prelogin,
    });
  }

  it.each(VECTORS)(
    "%s learns its KDF from prelogin",
    async (name) => {
      const vector = seed(name);

      const prelogin = await loginClient().get_password_prelogin(vector.account.email);

      expect(prelogin.kdf).toEqual(vector.account.kdf);
      expect(prelogin.salt).toEqual(vector.account.email);
    },
    TIMEOUT,
  );

  it.each(VECTORS)(
    "%s authenticates and is handed unlock data that opens its vault",
    async (name) => {
      const vector = seed(name);
      const client = loginClient();

      const prelogin = await client.get_password_prelogin(vector.account.email);
      const response = await login(client, vector, prelogin);

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
      const vector = seed("v1-pbkdf2-password");
      const client = loginClient();

      const prelogin = await client.get_password_prelogin(vector.account.email);

      await expect(login(client, vector, prelogin, "not-the-password")).rejects.toBeDefined();
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
