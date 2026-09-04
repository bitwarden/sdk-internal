// Shared setup for the tests that only decrypt committed data.
//
// No model server: these seed a vector straight into local state and open it. They are the baseline
// the rest of the suite rests on, so they deliberately depend on as little as possible.

import type { InitUserCryptoMethod } from "@bitwarden/sdk-internal";

import { LocalState } from "../model-server/local-state";
import { expectedVaultOf, validateLocalState } from "../model-server/validate";
import { loadUserVectors, toSeedAccount, type UserVector } from "../test-vectors/load";

/** A real KDF derivation per unlock, and some vectors use argon2id. */
export const UNLOCK_TIMEOUT = 120_000;

export const vectors = loadUserVectors();

/** `describe.each` rows. */
export const vectorCases = vectors.map((vector) => [vector.name, vector] as const);

/** Seeds `vector` into a fresh local state, unlocks with `method` and decrypts its whole vault. */
export async function validateVectorDirectly(
  vector: UserVector,
  method: InitUserCryptoMethod,
): Promise<void> {
  const account = toSeedAccount(vector);
  const local = new LocalState();

  await local.seedAccount({
    userId: account.account.userId,
    email: account.account.email,
    accountCryptographicState: account.account.accountCryptographicState,
    kdf: account.account.kdf,
    ...(account.account.upgradeToken === undefined
      ? {}
      : { upgradeToken: account.account.upgradeToken }),
    ...(account.account.organizationKeys === undefined
      ? {}
      : { organizationKeys: account.account.organizationKeys }),
  });
  await local.seedVault({
    ciphers: vector.vault.ciphers.map((item) => item.encrypted),
    folders: vector.vault.folders.map((item) => item.encrypted),
  });

  // Nothing has been written, so nothing may differ — not even the fields a write would restamp.
  await validateLocalState(local, method, expectedVaultOf(account), { ignore: [] });
}
