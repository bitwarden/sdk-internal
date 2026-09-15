// Shared setup for the tests that only decrypt committed data.
//
// A vector is seeded into the server emulator and synced down, as every other test does: the state
// a client decrypts from has to be state the SDK itself wrote, or the assertions read back the
// harness's own writes.

import type { InitUserCryptoMethod } from "@bitwarden/sdk-internal";

import { expectedVaultOf, validateLocalState } from "../../client-emulator/validate";
import { testHarness } from "../../test-harness";
import { loadUserVectors, toSeedAccount, type UserVector } from "../../vectors/load";

/** A real KDF derivation per unlock, and some vectors use argon2id. */
export const UNLOCK_TIMEOUT = 120_000;

export const vectors = loadUserVectors();

/** Seeds `vector` into the server, syncs it down, unlocks with `method` and decrypts its vault. */
export async function validateVector(
  vector: UserVector,
  method: InitUserCryptoMethod,
): Promise<void> {
  const account = toSeedAccount(vector);
  const harness = testHarness();

  try {
    const { email } = harness.server.seedUser(account);
    const client = harness.newClientEmulator();
    await client.login(email);

    // Nothing has been written, so nothing may differ — not even the fields a write would restamp.
    await validateLocalState(client.local, method, expectedVaultOf(account), { ignore: [] });
  } finally {
    harness.restore();
  }
}
