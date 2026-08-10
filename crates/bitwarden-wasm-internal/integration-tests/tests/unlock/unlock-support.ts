// Shared scaffolding for the unlock suites.
//
// Every suite here works off the committed user vectors and the (vector, method) matrix they imply, so
// the loading, the matrix and the "seed local state and validate" helper live in one place.

import type { InitUserCryptoMethod, PasswordManagerClient } from "@bitwarden/sdk-internal";

import { LocalState } from "../model-server/local-state";
import { validateLocalState } from "../model-server/sync";
import { loadUserVectors, unlockMethodName, type UserVector } from "../test-vectors/load";
import { makePasswordManagerClient, makeStateBridge } from "../utils";

/**
 * Unlocking runs real KDF iterations — up to 600k rounds of PBKDF2 — for every vector and every method,
 * so every suite here needs a generous budget.
 */
export const UNLOCK_TIMEOUT = 120_000;

/** The cheapest vector to unlock: PBKDF2 at 5,000 rounds rather than 600,000. */
export const CHEAPEST_VECTOR = "v1-pbkdf2-min-iterations";

export const vectors = loadUserVectors();

/** Every vector, shaped for `describe.each`. */
export const vectorCases = vectors.map((vector) => [vector.name, vector] as const);

/** Every (vector, method) pair in the set, as `it.each` table rows. */
export const allPairs = vectors.flatMap((vector) =>
  vector.unlockMethods.map(
    (method) => [vector.name, unlockMethodName(method), vector, method] as const,
  ),
);

/** Builds a client and unlocks it with `method`, loading organization keys if the account has any. */
export async function unlockWithOrganizations(
  vector: UserVector,
  method: InitUserCryptoMethod,
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

  const organizationKeys = vector.account.organizationKeys ?? {};
  if (Object.keys(organizationKeys).length > 0) {
    await client.crypto().initialize_org_crypto({
      organizationKeys: new Map(Object.entries(organizationKeys)) as never,
    });
  }

  return client;
}

/**
 * Seeds a `LocalState` straight from the vector and validates through the shared helper.
 *
 * No server is involved — these suites only decrypt committed data — so local state is seeded from the
 * vector rather than synced. It routes through the same validator as every other suite so there is one
 * definition of "the vault decrypts correctly".
 */
export async function validateVectorDirectly(vector: UserVector, method: InitUserCryptoMethod) {
  const local = new LocalState();
  await local.seedAccount({
    userId: vector.account.userId as unknown as string,
    email: vector.account.email,
    accountCryptographicState: vector.account.accountCryptographicState,
    kdf: vector.account.kdf,
    upgradeToken: vector.account.upgradeToken,
    organizationKeys: vector.account.organizationKeys ?? {},
  });
  await local.seedVault({
    ciphers: vector.vault.ciphers.map((item) => item.encrypted),
    folders: vector.vault.folders.map((item) => item.encrypted),
  });

  const result = await validateLocalState(
    local,
    method,
    { ciphers: vector.vault.ciphers, folders: vector.vault.folders },
    {
      expectedUserKey: vector.rawCryptographicState.userKey,
      expectedUserKeyId: vector.rawCryptographicState.userKeyId,
      // Nothing has been written, so nothing is volatile: compare the views exactly.
      ignore: [],
    },
  );
  expect(result.ciphers).toBeGreaterThan(0);
  return result;
}
