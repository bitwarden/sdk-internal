// Rotation as a user performs it: rotate, then carry on using the account.
//
// Two flows that are not tied to any unlock method. The first rotates the same account five times in a
// row, rebuilding the SDK from the server between each; the second rotates an account that shares its
// key with an organization and an emergency-access contact, and checks the shares were re-sealed.
//
// Each feature's own `conformance.test.ts` covers a single rotation per account type and asserts what
// gets posted. Neither of those consumes the result, so nothing there proves a rotation produces state
// the SDK can *load* — only that it produces state of the right shape. Anything that survives one round
// trip but degrades over successive generations is invisible to them: a key id that stops being
// regenerated, a security version that fails to advance, an unlock payload that happens to still work
// only because the original one did.
//
// The chain closes that loop. The model server plays the role the real backend plays: it serves the
// account's current state to `GET /sync`, absorbs `POST /rotate-user-keys`, and serves *that* on the next
// rotation. Between generations the client is thrown away and rebuilt from the served state and the
// master password alone, which is the only way to show the previous rotation's output is genuinely usable.
//
// Every generation is validated: the vault must decrypt to the plaintext the vector recorded, from the
// very first generation to the sixth. Because the expected plaintext comes from the committed vector and
// never changes, a mistake in the server's write handling shows up as a decryption failure rather than as
// a test that agrees with itself.

import type { PublicKey } from "@bitwarden/sdk-internal";

import { ApiServer } from "../model-server/api-server";
import { LocalState } from "../model-server/local-state";
import {
  syncToLocalState,
  unlockMethodFor,
  validateAfterLogoutLogin,
  validateVector,
} from "../model-server/sync";
import { installServers, type InstalledServers } from "../model-server/install";
import {
  assertRotationHarnessClean,
  ROTATION_TIMEOUT,
  setupRotation,
  type RotationHarness,
} from "../rotation-cases";
import {
  loadEmergencyAccessVectors,
  loadOrganizationVectors,
  loadUserVectors,
  userVector,
} from "../test-vectors/load";

// Five rotations, each re-deriving the master key, plus a validating decryption pass per generation.
const TIMEOUT = 300_000;

const ROTATIONS = 5;

const users = loadUserVectors();
const organizations = loadOrganizationVectors();
const emergencyAccess = loadEmergencyAccessVectors();

/**
 * `v1-argon2id-password` is the richest vault in the set that a rotation will actually accept: two
 * ciphers, a folder and a send, and — critically — no pre-v2 attachments, which
 * `check_for_old_attachments` refuses to rotate. Argon2 at 6 iterations also keeps five rotations quick.
 */
const vector = userVector(users, "v1-argon2id-password");

describe("successive key rotations", () => {
  let api: ApiServer;
  let servers: InstalledServers;

  beforeEach(() => {
    api = new ApiServer();
    api.seedUser(vector);
    // No organizations or emergency-access grants are seeded: re-sharing needs trusted public keys
    // supplied per call and is covered by its own suite below, so leaving them out keeps the chain
    // about the account's own keys.
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
    `survives ${ROTATIONS} rotations, decrypting to the recorded plaintext at every generation`,
    async () => {
      const user = () => api.db.user(api.soleUserId());
      const wrappedPrivateKeyOf = () => {
        const state = user().accountCryptographicState;
        return ("V1" in state ? state.V1.private_key : state.V2.private_key).toString();
      };

      // Generation 0: the account exactly as committed. If this fails, nothing below means anything.
      const local = new LocalState();
      await syncToLocalState(api, vector.account.email, local);
      await validateVector(local, unlockMethodFor(api, vector.account.email), vector);

      const initial = await local.unlock(unlockMethodFor(api, vector.account.email));
      const userKeys: string[] = [(await initial.crypto().get_user_encryption_key()).toString()];
      expect(userKeys[0]).toBe(vector.rawCryptographicState.userKey);

      const securityVersions: number[] = [user().securityVersion];
      const wrappedUserKeys: string[] = [user().masterPasswordUnlock!.masterKeyWrappedUserKey];
      const publicKeys: string[] = [user().publicKey];
      const wrappedPrivateKeys: string[] = [wrappedPrivateKeyOf()];

      for (let generation = 1; generation <= ROTATIONS; generation++) {
        // Act: rotate from a client rebuilt on the previous generation's state.
        const rotating = await local.unlock(unlockMethodFor(api, vector.account.email));
        await rotating.user_crypto_management().rotate_user_keys({
          key_rotation_method: { Password: { password: vector.account.password } },
          trusted_emergency_access_public_keys: [],
          trusted_organization_public_keys: [],
          upgrade_token_action: "Skip",
        });

        // Assert: log out and back in. Local state is discarded, the rotation is synced down, and the
        // account is unlocked from nothing but what the server holds — so unlocking at all proves the
        // rotation's output is loadable.
        const next = await validateAfterLogoutLogin(api, vector.account.email, vector, {
          // A rotation mints a new user key by definition, so the vector's recorded one no longer
          // applies from here on.
          expectedUserKey: undefined,
        });

        const rebuilt = await next.unlock(unlockMethodFor(api, vector.account.email));
        userKeys.push((await rebuilt.crypto().get_user_encryption_key()).toString());
        securityVersions.push(user().securityVersion);
        wrappedUserKeys.push(user().masterPasswordUnlock!.masterKeyWrappedUserKey);
        publicKeys.push(user().publicKey);
        wrappedPrivateKeys.push(wrappedPrivateKeyOf());
        await syncToLocalState(api, vector.account.email, local);
      }

      // Every generation must be genuinely new material, not a re-post of the last one.
      expect(new Set(userKeys).size).toBe(ROTATIONS + 1);
      expect(new Set(wrappedUserKeys).size).toBe(ROTATIONS + 1);

      // The identity key pair, on the other hand, must survive rotation unchanged. Regenerating it
      // would invalidate every organization and emergency-access share the account is party to, and
      // force every peer to re-trust the new key. Rotation re-wraps the *same* private key under the
      // new user key instead, so the public half is stable while every wrapping differs.
      expect(new Set(publicKeys).size).toBe(1);
      expect(publicKeys[0]).toBe(vector.rawCryptographicState.publicKey);
      expect(new Set(wrappedPrivateKeys).size).toBe(ROTATIONS + 1);

      // The account starts V1 and is V2 from the first rotation onwards, never regressing.
      expect(securityVersions[0]).toBe(1);
      for (const version of securityVersions.slice(1)) {
        expect(version).toBeGreaterThanOrEqual(2);
      }

      // The original user key is dead: it must not be reachable again at any later generation.
      expect(userKeys.slice(1)).not.toContain(vector.rawCryptographicState.userKey);
    },
    TIMEOUT,
  );
});

describe("key rotation re-sharing", () => {
  let harness: RotationHarness;

  afterEach(() => assertRotationHarnessClean(harness));

  it(
    "re-shares the user key to trusted organizations and emergency access contacts",
    async () => {
      // The only account that is both enrolled in account recovery and an emergency-access grantor
      // while carrying no pre-v2 attachments, so it can actually complete a rotation.
      const sharingVector = userVector(users, "v2-argon2id-blob");
      harness = setupRotation(sharingVector);
      const { api } = harness;
      const local = new LocalState();
      await syncToLocalState(api, sharingVector.account.email, local);
      const client = await local.unlock(unlockMethodFor(api, sharingVector.account.email));

      const organization = organizations.find((o) =>
        o.members.some(
          (member) =>
            member.userVector === sharingVector.name && member.accountRecoveryKey !== undefined,
        ),
      )!;
      const grant = emergencyAccess.find((g) => g.grantorVector === sharingVector.name)!;

      await client.user_crypto_management().rotate_user_keys({
        key_rotation_method: { Password: { password: sharingVector.account.password } },
        trusted_emergency_access_public_keys: [grant.granteePublicKey as unknown as PublicKey],
        trusted_organization_public_keys: [organization.publicKey as unknown as PublicKey],
        upgrade_token_action: "Skip",
      });

      // Read back off the account the server stored, not the request body.
      const stored = api.db.user(api.soleUserId());

      // The new user key is re-sealed to each trusted party. The ciphertexts must differ from the
      // committed ones, which were sealed against the *old* user key.
      expect(stored.accountRecoveryUnlockData).toHaveLength(1);
      expect(stored.emergencyAccessUnlockData).toHaveLength(1);

      const member = organization.members.find((m) => m.userVector === sharingVector.name)!;
      expect(stored.accountRecoveryUnlockData[0].resetPasswordKey).not.toBe(
        member.accountRecoveryKey!.toString(),
      );
      expect(stored.emergencyAccessUnlockData[0].keyEncrypted).not.toBe(
        grant.grantorUserKeySealedToGrantee.toString(),
      );
    },
    ROTATION_TIMEOUT,
  );
});
