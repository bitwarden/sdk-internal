// Two rotation cases worth pinning down so they cannot regress, neither tied to an unlock method.
//
// The first is a deliberate non-write: with `upgrade_token_action: "Skip"` a rotation leaves local state
// alone, so a client that trusted local state instead of re-syncing is left holding the old key. The
// second is a refusal: an account whose vault still carries pre-v2 attachments cannot be rotated at all.

import { ApiServer } from "../model-server/api-server";
import { LocalState, SETTINGS } from "../model-server/local-state";
import { syncToLocalState, unlockMethodFor } from "../model-server/sync";
import { installServers, type InstalledServers } from "../model-server/install";
import {
  assertRotationHarnessClean,
  ROTATION_ROUTES,
  ROTATION_TIMEOUT,
  setupRotation,
  type RotationHarness,
} from "../rotation-cases";
import { loadUserVectors, userVector } from "../test-vectors/load";
import { makePasswordManagerClient, makeStateBridge } from "../utils";

const users = loadUserVectors();

describe("rotation and local state", () => {
  // Same account as the rotation chain: the richest vault a rotation will actually accept.
  const vector = userVector(users, "v1-argon2id-password");

  let api: ApiServer;
  let servers: InstalledServers;

  beforeEach(() => {
    api = new ApiServer();
    api.seedUser(vector);
    servers = installServers({ api });
  });

  afterEach(() => {
    expect(servers.unmatched.map((request) => request.route)).toEqual([]);
    // No seeded account's password, user key, private key or master key may ever appear in a request
    // body. Policed by the server on every request, so no individual test has to remember to look.
    expect(api.secretLeaks()).toEqual([]);
    servers.restore();
  });

  it(
    "leaves local state untouched when the upgrade token is skipped",
    async () => {
      // `rotate_user_keys` only writes the account state, user key and token to the state bridge when it
      // created an upgrade token. With `Skip` it writes nothing, so a client that relied on local state
      // rather than a follow-up sync would still be holding the pre-rotation key.
      const bridge = makeStateBridge();
      const client = makePasswordManagerClient(bridge, SETTINGS);
      await client.crypto().initialize_user_crypto({
        userId: vector.account.userId,
        kdfParams: vector.account.kdf,
        email: vector.account.email,
        accountCryptographicState: vector.account.accountCryptographicState,
        method: vector.unlockMethods[0],
        upgradeToken: vector.account.upgradeToken,
      });

      await client.user_crypto_management().rotate_user_keys({
        key_rotation_method: { Password: { password: vector.account.password } },
        trusted_emergency_access_public_keys: [],
        trusted_organization_public_keys: [],
        upgrade_token_action: "Skip",
      });

      expect(await bridge.get_v2_upgrade_token()).toBeFalsy();
      expect(await bridge.get_account_cryptographic_state()).toBeFalsy();
    },
    ROTATION_TIMEOUT,
  );
});

describe("key rotation with pre-v2 attachments", () => {
  let harness: RotationHarness;

  afterEach(() => assertRotationHarnessClean(harness));

  it(
    "refuses to rotate an account whose vault still has pre-v2 attachments",
    async () => {
      // An attachment with no key has its contents encrypted under the user key, so rotating would make
      // the file unreadable. `check_for_old_attachments` fails the rotation before anything is posted.
      const vector = userVector(users, "v1-pbkdf2-password");
      expect(
        vector.vault.ciphers.some((cipher) =>
          Object.values(cipher.keys.attachments).some((attachment) => attachment.version !== "V2"),
        ),
      ).toBe(true);

      harness = setupRotation(vector);
      const { api, servers } = harness;
      const local = new LocalState();
      await syncToLocalState(api, vector.account.email, local);
      const client = await local.unlock(unlockMethodFor(api, vector.account.email));

      await expect(
        client.user_crypto_management().rotate_user_keys({
          key_rotation_method: { Password: { password: vector.account.password } },
          trusted_emergency_access_public_keys: [],
          trusted_organization_public_keys: [],
          upgrade_token_action: "Skip",
        }),
      ).rejects.toBeDefined();

      // Nothing was posted: the check runs before any re-encryption.
      expect(servers.routes()).not.toContain(ROTATION_ROUTES.rotate);
      // And the account on the server is untouched — still V1.
      expect("V1" in api.db.user(api.soleUserId()).accountCryptographicState).toBe(true);
    },
    ROTATION_TIMEOUT,
  );
});
