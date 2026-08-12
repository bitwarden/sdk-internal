// Shared scaffolding for the organization vector suites.
//
// An organization cipher is reached through a different key path than a personal one: the item key is
// wrapped by the *organization* key, which itself arrives sealed to the member's public key and is
// unsealed by `initialize_org_crypto`. Every suite below needs the same two things — the loaded vectors,
// and a way to resolve a member back to the user vector it names.

import {
  loadOrganizationVectors,
  loadUserVectors,
  userVector,
  type OrganizationVector,
  type UserVector,
} from "../test-vectors/load";
import { LocalState } from "../model-server/local-state";
import { validateLocalState } from "../model-server/sync";

/** Unlocking a member runs real KDF iterations — up to 600k rounds of PBKDF2 — once per member. */
export const ORGANIZATION_TIMEOUT = 120_000;

export const organizations = loadOrganizationVectors();
export const users = loadUserVectors();

/** Every organization vector, shaped for `describe.each`. */
export const organizationCases = organizations.map((vector) => [vector.name, vector] as const);

/** Resolves a member back to the user vector it names, failing loudly if the reference is dangling. */
export function memberVector(vector: OrganizationVector, index: number): UserVector {
  return userVector(users, vector.members[index].userVector);
}

/**
 * Seeds a `LocalState` with the member's account and the *organization's* vault, then validates through
 * the shared helper.
 *
 * The organization's items are what local state holds, so the same validator that checks a personal
 * vault checks a shared one — the only difference is whose keys unseal it.
 */
export async function validateOrganizationVaultFor(
  vector: OrganizationVector,
  user: UserVector,
): Promise<{ ciphers: number }> {
  const local = new LocalState();
  await local.seedAccount({
    userId: user.account.userId as unknown as string,
    email: user.account.email,
    accountCryptographicState: user.account.accountCryptographicState,
    kdf: user.account.kdf,
    upgradeToken: user.account.upgradeToken,
    organizationKeys: user.account.organizationKeys ?? {},
  });
  await local.seedVault({
    ciphers: vector.vault.ciphers.map((item) => item.encrypted),
    folders: vector.vault.folders.map((item) => item.encrypted),
  });

  const result = await validateLocalState(
    local,
    user.unlockMethods[0],
    { ciphers: vector.vault.ciphers, folders: vector.vault.folders },
    {
      expectedUserKey: user.rawCryptographicState.userKey,
      expectedUserKeyId: user.rawCryptographicState.userKeyId,
      // Nothing has been written, so nothing is volatile: compare the views exactly.
      ignore: [],
    },
  );
  expect(result.ciphers).toBe(vector.vault.ciphers.length);
  return result;
}
