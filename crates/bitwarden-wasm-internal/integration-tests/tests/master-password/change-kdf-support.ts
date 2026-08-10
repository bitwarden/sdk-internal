// The shared harness for `change_kdf`.
//
// A KDF change needs an unlocked account whose master-password unlock data is real, so the harness seeds
// a committed vector into the model server, syncs it into local state and unlocks it — the same route a
// client takes. Tests get the server, the local state and the unlocked client together.

import type { Kdf, PasswordManagerClient } from "@bitwarden/sdk-internal";

import type { Routes } from "../http-mock";
import { ApiServer } from "../model-server/api-server";
import { installServers, type InstalledServers } from "../model-server/install";
import { LocalState } from "../model-server/local-state";
import { syncToLocalState, unlockMethodFor } from "../model-server/sync";
import { loadUserVectors, userVector, type UserVector } from "../test-vectors/load";

/** Two KDF derivations per change — the old one to prove possession, the new one to re-wrap. */
export const CHANGE_KDF_TIMEOUT = 120_000;

export const CHANGE_KDF_ROUTE = "POST /accounts/kdf";

/** The server's numeric `KdfType`. */
export const KDF_TYPE = { pbkdf2Sha256: 0, argon2id: 1 } as const;

export const NEW_PBKDF2: Kdf = { pBKDF2: { iterations: 700_000 } };
export const NEW_ARGON2: Kdf = { argon2id: { iterations: 3, memory: 16, parallelism: 4 } };

const users = loadUserVectors();

/**
 * The cheapest master-password account in the set to unlock, so the cost of a test is dominated by the
 * KDF being changed *to* rather than the one being changed from.
 */
export const CHANGE_KDF_VECTOR = userVector(users, "v1-pbkdf2-min-iterations");

/** An account with no master password at all, for the case where there is no unlock data to re-derive. */
export const NO_MASTER_PASSWORD_VECTOR = userVector(users, "v1-argon2id-tde");

export interface ChangeKdfHarness {
  api: ApiServer;
  servers: InstalledServers;
  local: LocalState;
  client: PasswordManagerClient;
  vector: UserVector;
  assertClean(): void;
}

/**
 * Seeds `vector`, installs the API model, syncs the account into local state and unlocks it.
 *
 * `extraRoutes` overrides endpoints on the API origin, which is how the failure cases make the KDF
 * change be rejected without disturbing the rest of the model.
 */
export async function setupChangeKdf(
  options: { vector?: UserVector; extraRoutes?: Routes } = {},
): Promise<ChangeKdfHarness> {
  const vector = options.vector ?? CHANGE_KDF_VECTOR;
  const api = new ApiServer();
  api.seedUser(vector);
  const servers = installServers({ api, extraRoutes: options.extraRoutes });

  const local = new LocalState();
  await syncToLocalState(api, vector.account.email, local);
  const client = await local.unlock(unlockMethodFor(api, vector.account.email));

  return {
    api,
    servers,
    local,
    client,
    vector,
    assertClean() {
      expect(servers.unmatched.map((request) => request.route)).toEqual([]);
      // No seeded account's password, user key, private key or master key may ever appear in a request
      // body. Policed by the server on every request, so no individual test has to remember to look.
      expect(api.secretLeaks()).toEqual([]);
      servers.restore();
    },
  };
}
