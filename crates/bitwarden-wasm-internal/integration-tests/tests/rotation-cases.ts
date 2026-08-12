// The shared body of a key-rotation case, so each feature can assert its own accounts without
// re-deriving the setup.
//
// A rotation touches everything at once — the account cryptographic state, every vault item, the
// primary unlock method and every shared key — so what has to be asserted is the same regardless of how
// the rotation was authorized. Only the accounts and the expected unlock method differ, which is what
// each feature's own suite supplies.

import type { KeyRotationMethod, PublicKey } from "@bitwarden/sdk-internal";

import { ApiServer } from "./model-server/api-server";
import { installServers, type InstalledServers } from "./model-server/install";
import { KeyConnectorServer } from "./model-server/key-connector-server";
import { LocalState } from "./model-server/local-state";
import { syncToLocalState, unlockMethodFor, validateAfterLogoutLogin } from "./model-server/sync";
import {
  loadEmergencyAccessVectors,
  loadOrganizationVectors,
  type UserVector,
} from "./test-vectors/load";

/** A rotation re-derives the master key, so it pays the KDF cost on top of unlocking. */
export const ROTATION_TIMEOUT = 120_000;

/** `UnlockMethod` as the server model numbers it. */
export const UNLOCK_METHOD = { tde: 0, masterPassword: 1, keyConnector: 2 } as const;

export const ROTATION_ROUTES = {
  accountKeys: "GET /accounts/keys",
  sync: "GET /sync",
  keyRotationData: "GET /accounts/key-management/key-rotation-data",
  rotate: "POST /accounts/key-management/rotate-user-keys",
  keyConnectorUserKeys: "GET /user-keys",
} as const;

export interface RotationCase {
  /** The user vector to rotate. */
  vector: UserVector;
  /** How to authorize the rotation. */
  method: (vector: UserVector) => KeyRotationMethod;
  /** The `unlockMethod` the rotated account should declare. */
  expectedUnlockMethod: number;
  /** The key connector key to serve, for a key-connector rotation. */
  keyConnectorKey?: string;
}

export interface RotationHarness {
  api: ApiServer;
  keyConnector: KeyConnectorServer;
  servers: InstalledServers;
}

const organizations = loadOrganizationVectors();
const emergencyAccess = loadEmergencyAccessVectors();

/** Seeds the account plus every organization and emergency-access grant, and installs the servers. */
export function setupRotation(vector: UserVector, keyConnectorKey?: string): RotationHarness {
  const api = new ApiServer();
  api.seedUser(vector);
  for (const organization of organizations) {
    api.seedOrganization(organization);
  }
  api.seedEmergencyAccess(emergencyAccess);

  const keyConnector = new KeyConnectorServer();
  if (keyConnectorKey !== undefined) {
    keyConnector.seedKey(keyConnectorKey);
  }

  return { api, keyConnector, servers: installServers({ api, keyConnector }) };
}

/** The assertions every rotation suite makes in `afterEach`. */
export function assertRotationHarnessClean(harness: RotationHarness): void {
  expect(harness.servers.unmatched.map((request) => request.route)).toEqual([]);
  // No seeded account's password, user key, private key or master key may ever appear in a request
  // body. Policed by the server on every request, so no individual test has to remember to look.
  expect(harness.api.secretLeaks()).toEqual([]);
  harness.servers.restore();
}

/**
 * Rotates `rotationCase`'s account and asserts the result, from the account the server now holds.
 *
 * Shared by every feature's rotation suite. If this stops asserting, every rotation case silently
 * passes — so a change here should be checked by breaking one assertion and confirming all of them
 * fail.
 */
export async function expectRotationSucceeds(
  harness: RotationHarness,
  rotationCase: RotationCase,
): Promise<void> {
  const { api, servers } = harness;
  const { vector } = rotationCase;

  const local = new LocalState();
  await syncToLocalState(api, vector.account.email, local);
  const client = await local.unlock(unlockMethodFor(api, vector.account.email));

  // The organization and emergency-access public keys the user would have confirmed in the UI.
  const trustedOrganizationKeys = organizations
    .filter((organization) =>
      organization.members.some(
        (member) => member.userVector === vector.name && member.accountRecoveryKey !== undefined,
      ),
    )
    .map((organization) => organization.publicKey as unknown as PublicKey);
  const trustedEmergencyAccessKeys = emergencyAccess
    .filter((grant) => grant.grantorVector === vector.name)
    .map((grant) => grant.granteePublicKey as unknown as PublicKey);

  await client.user_crypto_management().rotate_user_keys({
    key_rotation_method: rotationCase.method(vector),
    trusted_emergency_access_public_keys: trustedEmergencyAccessKeys,
    trusted_organization_public_keys: trustedOrganizationKeys,
    upgrade_token_action: "Skip",
  });

  // A rotation reads the account, reads its rotation data, and posts the result.
  expect(servers.routes()).toContain(ROTATION_ROUTES.sync);
  expect(servers.routes()).toContain(ROTATION_ROUTES.keyRotationData);
  expect(servers.routes()).toContain(ROTATION_ROUTES.rotate);
  if (rotationCase.keyConnectorKey !== undefined) {
    // A key-connector rotation fetches the key from the connector rather than deriving it.
    expect(servers.routes()).toContain(ROTATION_ROUTES.keyConnectorUserKeys);
  }

  // Everything below reads the account the server now holds, never the request that produced it.
  // A request body only shows what the client intended; the stored account is what a client has
  // to live with afterwards.
  const stored = api.db.user(api.soleUserId());

  // Rotation always lands on a V2 state: a COSE-wrapped private key (`7.`), a signature key pair
  // and a signed security state.
  expect("V2" in stored.accountCryptographicState).toBe(true);
  expect(stored.accountCryptographicState.V2.private_key).toMatch(/^7\./);
  expect(stored.accountCryptographicState.V2.signing_key).toMatch(/^7\./);
  expect(stored.securityVersion).toBeGreaterThanOrEqual(2);
  expect(stored.unlockMethod).toBe(rotationCase.expectedUnlockMethod);

  // Every vault item survives, and every cipher is blob-encrypted, because rotation always lands
  // the account on the V2 security state.
  expect(api.db.ciphersFor(stored.userId)).toHaveLength(vector.vault.ciphers.length);
  expect(api.db.foldersFor(stored.userId)).toHaveLength(vector.vault.folders.length);
  expect(api.db.sendsFor(stored.userId)).toHaveLength(vector.vault.sends.length);
  for (const cipher of api.db.ciphersFor(stored.userId)) {
    expect((cipher as any).data).toBeTruthy();
  }

  // The real proof that the rotation is usable: throw the client away and open the account again
  // from nothing but what the server holds, then decrypt the whole vault.
  //
  // Master-password and key-connector accounts are both re-opened here: the server records the
  // re-derived master-password unlock data and the re-wrapped key-connector user key, so
  // `unlockMethodFor` rebuilds the post-rotation method in each case.
  //
  // TDE is the exception. Its rotated unlock data rides in `unlockData.deviceKeyUnlockData`, which
  // the SDK derives from the `trustedDeviceKeyData` the rotation-data endpoint serves. Seeding a
  // trusted device there needs the device's public key encrypted under the *user* key, and the
  // committed vectors record only `protected_device_private_key` and `device_protected_user_key` —
  // so there is nothing to seed it from until the generator emits that field. Until then the model
  // serves an empty device list, the rotation re-encrypts nothing, and a TDE account's stored unlock
  // data stays the pre-rotation copy.
  //
  // Logout/login only, deliberately: a rotation with `upgrade_token_action: "Skip"` writes nothing
  // to local state, so the writing client is *expected* to be left holding the old keys. That
  // staleness is asserted on its own in `key-rotation/edge-cases.test.ts`; asserting lock/unlock here
  // would be asserting the pre-rotation account.
  const reopenable =
    stored.masterPasswordUnlock !== null || stored.keyConnectorKeyWrappedUserKey !== undefined;
  if (reopenable) {
    await validateAfterLogoutLogin(api, vector.account.email, vector, {
      // A rotation mints a new user key, so the vector's recorded one no longer applies.
      expectedUserKey: undefined,
    });
  }
}
