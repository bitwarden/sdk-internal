// Account registration: the client generates its own key material and the server stores it.
//
// These tests assert the round trip rather than the request body. A registration that posts a
// well-formed but unusable state would pass a body check and still leave an account nobody can
// open, so each case registers, then logs in and unlocks what it just created.

import { SETTINGS } from "../../client-emulator/local-state";
import { KEY_CONNECTOR_URL } from "../../server-emulator/urls";
import { testHarness, type TestHarness } from "../../test-harness";
import { makePasswordManagerClient, makeStateBridge } from "../utils";
import {
  loadOrganizationVectors,
  loadUserVectors,
  toSeedAccount,
  toSeedOrganization,
  userVector,
} from "../../vectors/load";

import { asB64, asOrganizationId, asUserId } from "../type-assertion-helpers";

import type { LoginRequest, PasswordManagerClient } from "@bitwarden/sdk-internal";

/** A real KDF derivation per registration and per login. */
const TIMEOUT = 120_000;

const EMAIL = "registered@test.bitwarden.com";
const PASSWORD = "password-registered";
const DEVICE_IDENTIFIER = "integration-test-device";
const SSO_IDENTIFIER = "example-org";

/** The organization member standing in for an SSO-provisioned account. */
const SSO_MEMBER = "v1-argon2id-password";

const LOGIN_REQUEST: LoginRequest = {
  clientId: "web",
  device: {
    deviceType: "SDK",
    deviceIdentifier: "integration-test-device",
    deviceName: "Integration Tests",
    devicePushToken: undefined,
  },
};

/** The fields a password registration leaves unset — invites, tokens and provider flows. */
const NO_INVITES = {
  master_password_hint: undefined,
  email_verification_token: undefined,
  sales_assisted_token: undefined,
  organization_user_id: undefined,
  org_invite_token: undefined,
  org_sponsored_free_family_plan_token: undefined,
  accept_emergency_access_invite_token: undefined,
  accept_emergency_access_id: undefined,
  provider_invite_token: undefined,
  provider_user_id: undefined,
  open_org_invite: undefined,
} as const;

describe("account registration", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  });

  afterEach(() => harness.restore());

  function unauthenticatedClient(): PasswordManagerClient {
    return makePasswordManagerClient(makeStateBridge(), SETTINGS);
  }

  describe("post_keys_for_user_password_registration", () => {
    it(
      "creates an account whose vault the registering client can open",
      async () => {
        const client = unauthenticatedClient();

        const registered = await client
          .auth()
          .registration()
          .post_keys_for_user_password_registration({
            email: EMAIL,
            salt: EMAIL,
            master_password: PASSWORD,
            ...NO_INVITES,
          });

        // A registration builds a V2 state, and the server has to have kept every part of it: a
        // signing key and security state are what make the account V2 rather than V1.
        const user = harness.server.getUser(EMAIL);
        expect(user.securityVersion).toBe(2);
        expect(user.verifyingKey).not.toBeNull();
        expect("V2" in user.accountCryptographicState).toBe(true);
        expect(user.accountCryptographicState).toEqual(registered.account_cryptographic_state);

        // The state is usable: the returned user key opens the account it was generated for.
        const unlocked = makePasswordManagerClient(makeStateBridge(), SETTINGS);
        await unlocked.crypto().initialize_user_crypto({
          userId: user.userId as never,
          kdfParams: user.kdf,
          email: EMAIL,
          accountCryptographicState: user.accountCryptographicState,
          method: { decryptedKey: { decrypted_user_key: String(registered.user_key) } },
        });
        expect(await unlocked.crypto().get_user_encryption_key()).toEqual(
          String(registered.user_key),
        );
      },
      TIMEOUT,
    );

    it(
      "leaves the account able to log in and unlock with its master password",
      async () => {
        const client = unauthenticatedClient();

        const registered = await client
          .auth()
          .registration()
          .post_keys_for_user_password_registration({
            email: EMAIL,
            salt: EMAIL,
            master_password: PASSWORD,
            ...NO_INVITES,
          });

        const login = client.auth().login(SETTINGS);
        const prelogin = await login.get_password_prelogin(EMAIL);
        const response = await login.login_via_password({
          loginRequest: LOGIN_REQUEST,
          email: EMAIL,
          password: PASSWORD,
          preloginResponse: prelogin,
        });

        // The unlock data the login hands back is the data the registration posted, and the master
        // password recovers the same user key the registration generated.
        const unlock = response.Authenticated.userDecryptionOptions.masterPasswordUnlock;
        expect(unlock).toEqual(registered.master_password_unlock);

        const returning = makePasswordManagerClient(makeStateBridge(), SETTINGS);
        await returning.crypto().initialize_user_crypto({
          userId: harness.server.getUser(EMAIL).userId as never,
          kdfParams: prelogin.kdf,
          email: EMAIL,
          accountCryptographicState: registered.account_cryptographic_state,
          method: { masterPasswordUnlock: { password: PASSWORD, master_password_unlock: unlock! } },
        });
        expect(await returning.crypto().get_user_encryption_key()).toEqual(
          String(registered.user_key),
        );
      },
      TIMEOUT,
    );

    it(
      "refuses a second registration of the same email",
      async () => {
        const register = () =>
          unauthenticatedClient()
            .auth()
            .registration()
            .post_keys_for_user_password_registration({
              email: EMAIL,
              salt: EMAIL,
              master_password: PASSWORD,
              ...NO_INVITES,
            });

        await register();
        await expect(register()).rejects.toBeDefined();
      },
      TIMEOUT,
    );
  });
  /**
   * An account SSO provisioned but which has no unlock method yet.
   *
   * This is the precondition every registration below shares: the account exists and can
   * authenticate, but nothing can open its vault until the client gives it keys. Dropping the
   * vector's unlock methods leaves exactly that.
   */
  function seedSsoAccount(name: string) {
    const vector = userVector(loadUserVectors(), name);
    const account = { ...toSeedAccount(vector), unlockMethods: [] };
    delete account.masterPasswordAuthenticationHash;

    const seeded = harness.server.seedUser(account);
    expect(harness.server.getUser(seeded.email).masterPasswordUnlock).toBeNull();

    return { ...seeded, vector };
  }

  /**
   * The organization the SSO-provisioned account is a member of, and its recovery public key.
   *
   * The organization resolves its members by email, so every member's account has to exist first.
   * The one named by `ssoMember` is seeded without an unlock method; the rest are seeded whole.
   */
  function seedOrganization(ssoMember: string) {
    const [vector] = loadOrganizationVectors();
    if (vector === undefined) {
      throw new Error("no organization vectors");
    }

    const sso = seedSsoAccount(ssoMember);
    for (const member of vector.members) {
      if (member.userVector !== ssoMember) {
        harness.server.seedUser(toSeedAccount(userVector(loadUserVectors(), member.userVector)));
      }
    }

    harness.server.seedOrganization(toSeedOrganization(vector));

    return { organization: vector, sso };
  }

  /** The account's membership of an organization, which is where account recovery is recorded. */
  function memberOf(organizationId: string, userId: string) {
    const member = harness.server.db.organizations
      .get(organizationId)
      ?.members.find((candidate) => candidate.userId === userId);
    if (member === undefined) {
      throw new Error(`no membership of ${organizationId} for ${userId}`);
    }

    return member;
  }

  /** A client that can authenticate as `userId` but holds no keys of its own. */
  function clientFor(userId: string): PasswordManagerClient {
    return makePasswordManagerClient(makeStateBridge(), SETTINGS, userId);
  }

  describe("post_keys_for_tde_registration", () => {
    it(
      "gives a trusted-device account keys, account recovery and a device key",
      async () => {
        const { organization, sso } = seedOrganization(SSO_MEMBER);
        const { email, userId } = sso;
        const client = clientFor(userId);

        const registered = await client
          .auth()
          .registration()
          .post_keys_for_tde_registration({
            org_id: asOrganizationId(organization.organizationId),
            org_public_key: asB64(organization.publicKey),
            user_id: asUserId(userId),
            device_identifier: DEVICE_IDENTIFIER,
            trust_device: true,
          });

        // The account's stale V1 keys were replaced by the V2 state the client just built.
        const user = harness.server.getUser(email);
        expect(user.securityVersion).toBe(2);
        expect(user.accountCryptographicState).toEqual(registered.account_cryptographic_state);

        // The organization can recover the account, and the device can unlock it.
        const member = memberOf(organization.organizationId, userId);
        expect(member.accountRecoveryKey).toBeDefined();
        const deviceKeys = user.trustedDeviceKeys?.[DEVICE_IDENTIFIER];
        expect(deviceKeys).toBeDefined();

        const unlocked = clientFor(userId);
        await unlocked.crypto().initialize_user_crypto({
          userId: asUserId(userId),
          kdfParams: user.kdf,
          email,
          accountCryptographicState: user.accountCryptographicState,
          method: {
            deviceKey: {
              device_key: String(registered.device_key),
              protected_device_private_key: deviceKeys!.protectedDevicePrivateKey as never,
              device_protected_user_key: deviceKeys!.deviceProtectedUserKey as never,
            },
          },
        });
        expect(await unlocked.crypto().get_user_encryption_key()).toEqual(
          String(registered.user_key),
        );
      },
      TIMEOUT,
    );

    it(
      "stores no device key when the device is not trusted",
      async () => {
        const { organization, sso } = seedOrganization(SSO_MEMBER);
        const { email, userId } = sso;

        await clientFor(userId)
          .auth()
          .registration()
          .post_keys_for_tde_registration({
            org_id: asOrganizationId(organization.organizationId),
            org_public_key: asB64(organization.publicKey),
            user_id: asUserId(userId),
            device_identifier: DEVICE_IDENTIFIER,
            trust_device: false,
          });

        // Account recovery is still enrolled — only the device enrollment is conditional.
        expect(memberOf(organization.organizationId, userId).accountRecoveryKey).toBeDefined();
        expect(harness.server.getUser(email).trustedDeviceKeys).toBeUndefined();
      },
      TIMEOUT,
    );
  });

  describe("post_keys_for_jit_password_registration", () => {
    it(
      "sets the account's first master password and unlocks with it",
      async () => {
        const { organization, sso } = seedOrganization(SSO_MEMBER);
        const { email, userId } = sso;
        const client = clientFor(userId);

        const registered = await client
          .auth()
          .registration()
          .post_keys_for_jit_password_registration({
            org_id: asOrganizationId(organization.organizationId),
            org_public_key: asB64(organization.publicKey),
            organization_sso_identifier: SSO_IDENTIFIER,
            user_id: asUserId(userId),
            salt: email,
            master_password: PASSWORD,
            master_password_hint: undefined,
            reset_password_enroll: true,
          });

        const user = harness.server.getUser(email);
        expect(user.securityVersion).toBe(2);
        expect(memberOf(organization.organizationId, userId).accountRecoveryKey).toBeDefined();

        // The account can now log in with the password it was just given.
        const login = client.auth().login(SETTINGS);
        const prelogin = await login.get_password_prelogin(email);
        const response = await login.login_via_password({
          loginRequest: LOGIN_REQUEST,
          email,
          password: PASSWORD,
          preloginResponse: prelogin,
        });

        const unlock = response.Authenticated.userDecryptionOptions.masterPasswordUnlock;
        expect(unlock).toEqual(registered.master_password_unlock);

        const returning = clientFor(userId);
        await returning.crypto().initialize_user_crypto({
          userId: asUserId(userId),
          kdfParams: prelogin.kdf,
          email,
          accountCryptographicState: registered.account_cryptographic_state,
          method: { masterPasswordUnlock: { password: PASSWORD, master_password_unlock: unlock! } },
        });
        expect(await returning.crypto().get_user_encryption_key()).toEqual(
          String(registered.user_key),
        );
      },
      TIMEOUT,
    );
  });

  describe("post_keys_for_key_connector_registration", () => {
    it(
      "leaves the deployment holding a key that opens the account",
      async () => {
        const { email, userId } = seedSsoAccount(SSO_MEMBER);

        const registered = await clientFor(userId)
          .auth()
          .registration()
          .post_keys_for_key_connector_registration(KEY_CONNECTOR_URL, SSO_IDENTIFIER);

        // The key lives on the deployment; the server only holds the user key wrapped with it.
        expect(harness.server.keyConnector.storedUserKey(email)).toEqual(
          String(registered.key_connector_key),
        );
        const user = harness.server.getUser(email);
        expect(String(user.keyConnectorKeyWrappedUserKey)).toEqual(
          String(registered.key_connector_key_wrapped_user_key),
        );
        expect(user.masterPasswordUnlock).toBeNull();
        expect(user.securityVersion).toBe(2);

        // Fetching the key back from the deployment opens the account.
        const unlocked = clientFor(userId);
        await unlocked.crypto().initialize_user_crypto({
          userId: asUserId(userId),
          kdfParams: user.kdf,
          email,
          accountCryptographicState: registered.account_cryptographic_state,
          method: {
            keyConnectorUrl: {
              url: KEY_CONNECTOR_URL,
              key_connector_key_wrapped_user_key: registered.key_connector_key_wrapped_user_key,
            },
          },
        });
        expect(await unlocked.crypto().get_user_encryption_key()).toEqual(
          String(registered.user_key),
        );
      },
      TIMEOUT,
    );
  });
});
