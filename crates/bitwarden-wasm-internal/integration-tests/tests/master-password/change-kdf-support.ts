// The shared harness for `change_kdf`.
//
// A KDF change needs an unlocked account whose master-password unlock data is real, so the harness
// seeds an account into the model server, syncs it into local state and unlocks it — the same route
// a client takes. Tests get the server, the local state and the unlocked client together.

import type { Kdf, PasswordManagerClient } from "@bitwarden/sdk-internal";

import type { Routes } from "../http-mock";
import { ApiServer, type SeedAccount } from "../model-server/api-server";
import { installServers, type InstalledServers } from "../model-server/install";
import { LocalState } from "../model-server/local-state";
import {
  expectedVaultOf,
  syncToLocalState,
  unlockMethodFor,
  type ExpectedVault,
} from "../model-server/validate";
import { loadUserVectors, toSeedAccount, userVector } from "../test-vectors/load";

/** Two KDF derivations per change — the old one to prove possession, the new one to re-wrap. */
export const CHANGE_KDF_TIMEOUT = 120_000;

export const CHANGE_KDF_ROUTE = "POST /accounts/kdf";

export const NEW_PBKDF2: Kdf = { pBKDF2: { iterations: 700_000 } };
export const NEW_ARGON2: Kdf = { argon2id: { iterations: 3, memory: 16, parallelism: 4 } };

const users = loadUserVectors();

/**
 * The cheapest master-password account in the set to unlock, so a test's cost is dominated by the
 * KDF being changed *to* rather than the one being changed from.
 */
export const CHANGE_KDF_VECTOR = userVector(users, "v1-pbkdf2-min-iterations");

/** An account with no master password at all, so there is no unlock data to re-derive. */
export const NO_MASTER_PASSWORD_VECTOR = userVector(users, "v1-argon2id-tde");

export const CHANGE_KDF_ACCOUNT = toSeedAccount(CHANGE_KDF_VECTOR);
export const NO_MASTER_PASSWORD_ACCOUNT = toSeedAccount(NO_MASTER_PASSWORD_VECTOR);

export interface ChangeKdfHarness {
  api: ApiServer;
  servers: InstalledServers;
  local: LocalState;
  client: PasswordManagerClient;
  account: SeedAccount;
  email: string;
  /** The plaintext the account's vault must still decrypt to, keyed by item id. */
  expected: ExpectedVault;
  assertClean(): void;
}

/**
 * Seeds `account`, installs the API model, syncs the account into local state and unlocks it.
 *
 * `extraRoutes` overrides endpoints on the API origin, which is how the failure cases make the KDF
 * change be rejected without disturbing the rest of the model.
 */
export async function setupChangeKdf(
  options: { account?: SeedAccount; extraRoutes?: Routes } = {},
): Promise<ChangeKdfHarness> {
  const account = options.account ?? CHANGE_KDF_ACCOUNT;
  const api = new ApiServer();
  api.seedUser(account);
  const servers = installServers({ api, extraRoutes: options.extraRoutes });

  const email = account.account.email;
  const local = new LocalState();
  await syncToLocalState(api, email, local);
  const client = await local.unlock(unlockMethodFor(api, email));

  return {
    api,
    servers,
    local,
    client,
    account,
    email,
    expected: expectedVaultOf(account),
    assertClean() {
      expect(servers.unmatched.map((request) => request.route)).toEqual([]);
      // The account's password, user key and private key are watched by the server on every
      // request, so no individual test has to remember to look at a body.
      expect(api.secretLeaks()).toEqual([]);
      servers.restore();
    },
  };
}

/**
 * Asserts the vector's recorded user key is the one the account actually unwraps to.
 *
 * The server can only watch for a secret it was told about. If a vector's recorded user key ever
 * drifts from its key material, the leak check keeps passing while covering nothing — so it is
 * re-derived rather than trusted.
 */
export async function expectRecordedUserKeyIsLive(client: PasswordManagerClient): Promise<void> {
  expect(await client.crypto().get_user_encryption_key()).toBe(
    CHANGE_KDF_VECTOR.rawCryptographicState.userKey,
  );
}
