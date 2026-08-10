// Brings a client up from a committed user vector.
//
// Shared by the vector suites so they cannot drift on what "unlocked" means. Organization keys are
// loaded straight after the user key by default, which is the order a real client uses on login —
// `initialize_org_crypto` needs the user's private key to unseal them, so it cannot run first.

import type { InitUserCryptoMethod, PasswordManagerClient } from "@bitwarden/sdk-internal";

import { makePasswordManagerClient, makeStateBridge } from "../utils";

import type { UserVector } from "./load";

export interface UnlockOptions {
  /**
   * Whether to load the organization keys the account carries.
   *
   * Defaults to `true`. Pass `false` to reach the state of a user who belongs to an organization but
   * whose client has not loaded its key yet — the only way to test that organization data is
   * genuinely unreachable without it.
   */
  organizations?: boolean;
}

/** Builds a client and unlocks it with `method`. */
export async function unlockVector(
  vector: UserVector,
  method: InitUserCryptoMethod,
  options: UnlockOptions = {},
): Promise<PasswordManagerClient> {
  const client = makePasswordManagerClient(makeStateBridge());

  await client.crypto().initialize_user_crypto({
    userId: vector.account.userId,
    kdfParams: vector.account.kdf,
    email: vector.account.email,
    accountCryptographicState: vector.account.accountCryptographicState,
    method,
    upgradeToken: vector.account.upgradeToken,
  });

  if (options.organizations ?? true) {
    await loadOrganizationKeys(client, vector);
  }

  return client;
}

/**
 * Loads whatever organization keys the account carries, returning how many were loaded.
 *
 * A no-op for an account in no organization, so this is safe to call unconditionally.
 */
export async function loadOrganizationKeys(
  client: PasswordManagerClient,
  vector: UserVector,
): Promise<number> {
  const organizationKeys = vector.account.organizationKeys ?? {};
  const count = Object.keys(organizationKeys).length;

  if (count > 0) {
    await client.crypto().initialize_org_crypto({
      organizationKeys: new Map(Object.entries(organizationKeys)) as never,
    });
  }

  return count;
}
