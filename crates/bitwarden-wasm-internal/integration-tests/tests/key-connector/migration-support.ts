// The shared harness for `migrate_to_key_connector`, so the flow and the edge cases can each stand up
// the two servers without re-deriving the setup.
//
// A migration spans two independent origins — the API and the key connector — so every test needs both
// models installed together, and both are inspected afterwards.

import type { Routes } from "../http-mock";
import { ApiServer } from "../model-server/api-server";
import { installServers, type InstalledServers } from "../model-server/install";
import { KeyConnectorServer } from "../model-server/key-connector-server";
import { loadUserVectors, userVector, type UserVector } from "../test-vectors/load";

/** Unlocking to get a user key in memory pays the account's real KDF cost. */
export const MIGRATION_TIMEOUT = 120_000;

/** A key connector key is 32 raw bytes, sent base64. */
export const KEY_CONNECTOR_KEY_BYTES = 32;

const users = loadUserVectors();

/**
 * A V1 and a V2 account, because the user key being wrapped differs in kind: V1 is an
 * `Aes256CbcHmac` key, V2 an `XChaCha20Poly1305` COSE key, and `encrypt_user_key` encodes them
 * differently. `v1-pbkdf2-min-iterations` is also the cheapest vector in the set to unlock.
 */
export const MIGRATION_CASES: [string, UserVector][] = [
  ["a V1 account", userVector(users, "v1-pbkdf2-min-iterations")],
  ["a V2 account", userVector(users, "v2-argon2id-blob")],
];

export interface MigrationHarness {
  api: ApiServer;
  keyConnector: KeyConnectorServer;
  servers: InstalledServers;
}

/**
 * Stands up an API model and a key connector model on their own origins.
 *
 * Passing no vector leaves the API with no account at all, which is what the locked-client case needs.
 */
export function setupMigration(vector?: UserVector, extraRoutes?: Routes): MigrationHarness {
  const api = new ApiServer();
  if (vector !== undefined) {
    api.seedUser(vector);
  }
  const keyConnector = new KeyConnectorServer();
  return { api, keyConnector, servers: installServers({ api, keyConnector, extraRoutes }) };
}

/** The assertions every migration suite makes in `afterEach`. */
export function assertMigrationHarnessClean(harness: MigrationHarness): void {
  expect(harness.servers.unmatched.map((request) => request.route)).toEqual([]);
  // No seeded account's password, user key, private key or master key may ever appear in a request
  // body. Policed by the server on every request, so no individual test has to remember to look.
  expect(harness.api.secretLeaks()).toEqual([]);
  harness.servers.restore();
}
