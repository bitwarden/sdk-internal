// Shared scaffolding for the registration suites.

import type {
  InitUserCryptoMethod,
  Kdf,
  PasswordManagerClient,
  UserId,
  UserMasterPasswordRegistrationRequest,
  WrappedAccountCryptographicState,
} from "@bitwarden/sdk-internal";

import { ApiServer } from "./model-server/api-server";
import { installServers, type InstalledServers } from "./model-server/install";
import { KeyConnectorServer } from "./model-server/key-connector-server";
import { SETTINGS } from "./model-server/local-state";
import { loadOrganizationVectors } from "./test-vectors/load";
import { validateUserKey } from "./test-vectors/validate";
import { makePasswordManagerClient, makeStateBridge } from "./utils";

export const REGISTRATION_TIMEOUT = 180_000;

export const EMAIL = "registration@test.bitwarden.com";
export const PASSWORD = "correct horse battery staple";
/** Branded at the boundary, once, rather than cast at every use. */
export const USER_ID = "bc0f0000-0000-4000-8000-000000000000" as unknown as UserId;
export const DEVICE_IDENTIFIER = "device-1";

/** An organization to enroll into, reusing a committed org's real public key. */
export const organization = loadOrganizationVectors()[0];

export const passwordRegistrationRequest: UserMasterPasswordRegistrationRequest = {
  email: EMAIL,
  salt: EMAIL,
  master_password: PASSWORD,
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
};

export function newClient(): PasswordManagerClient {
  return makePasswordManagerClient(makeStateBridge(), SETTINGS);
}

export interface RegistrationHarness {
  api: ApiServer;
  keyConnector: KeyConnectorServer;
  servers: InstalledServers;
}

/** Installs the servers with the organization seeded, but no account. */
export function setupRegistration(): RegistrationHarness {
  const api = new ApiServer();
  api.seedOrganization(organization);
  const keyConnector = new KeyConnectorServer();
  return { api, keyConnector, servers: installServers({ api, keyConnector }) };
}

/** The assertions every registration suite makes in `afterEach`. */
export function assertRegistrationHarnessClean(harness: RegistrationHarness): void {
  expect(harness.servers.unmatched.map((request) => request.route)).toEqual([]);
  // No seeded account's password, user key, private key or master key may ever appear in a request
  // body. Policed by the server on every request, so no individual test has to remember to look.
  expect(harness.api.secretLeaks()).toEqual([]);
  harness.servers.restore();
}

/**
 * Unlocks a fresh client with `method` and asserts it reaches `expectedUserKey`.
 *
 * Also checks the state is a V2 one: registration always mints a V2 account, so a V1 state here would
 * mean the wrong branch ran.
 */
export async function unlockFreshAndValidate(
  accountCryptographicState: WrappedAccountCryptographicState,
  method: InitUserCryptoMethod,
  expectedUserKey: string,
  kdf: Kdf,
): Promise<void> {
  const client = newClient();
  await client.crypto().initialize_user_crypto({
    userId: USER_ID,
    kdfParams: kdf,
    email: EMAIL,
    accountCryptographicState,
    method,
  });

  await validateUserKey(client, expectedUserKey);
  expect("V2" in accountCryptographicState).toBe(true);
}
