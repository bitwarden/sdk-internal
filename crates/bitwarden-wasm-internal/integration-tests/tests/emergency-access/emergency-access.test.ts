import {
  EmergencyAccessStatus,
  EmergencyAccessType,
  type EmergencyAccessClient,
} from "@bitwarden/sdk-internal";

import { validateCiphers, validateVault } from "../../client-emulator/validate";
import {
  EmergencyAccessStatus as ServerStatus,
  EmergencyAccessType as ServerType,
} from "../../server-emulator/dto";
import type { SeededTestVector } from "../../server-emulator/server-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { loadEmergencyAccessVectors, type EmergencyAccessVector } from "../../vectors/load";
import { testVectors } from "../../vectors/test-vectors";
import { asB64, asEmergencyAccessId } from "../type-assertion-helpers";

const UNLOCK_TIMEOUT = 120_000;
const WAIT_TIME_DAYS = 7;
const NEW_PASSWORD = "a new master password set by the grantee";

const vectors = loadEmergencyAccessVectors();

/** Logs `account` in on a fresh client and unlocks it with its own password. */
async function unlocked(harness: TestHarness, account: SeededTestVector) {
  const client = harness.newClientEmulator();
  await client.login(account.email);
  await client.unlock(account.vector.account.password);

  return client;
}

/** An unlocked account's emergency access client. */
async function emergencyAccessOf(
  harness: TestHarness,
  account: SeededTestVector,
): Promise<EmergencyAccessClient> {
  return (await unlocked(harness, account)).getPasswordManagerClient().emergency_access();
}

/** Seeds a vector's grant at `status`, then unlocks both sides. */
async function seededGrant(
  harness: TestHarness,
  vector: EmergencyAccessVector,
  type: number,
  status: number,
) {
  const seeded = harness.server.seedEmergencyAccessTestVector(vector, { type, status });

  return {
    ...seeded,
    id: asEmergencyAccessId(seeded.id),
    grantorClient: await emergencyAccessOf(harness, seeded.grantor),
    granteeClient: await emergencyAccessOf(harness, seeded.grantee),
  };
}

describe("emergency access", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  });

  afterEach(() => {
    harness.restore();
  });

  describe("test vectors", () => {
    /**
     * We provide indefinite support for these test vectors. Any regression here means we dropped
     * support for some emergency access data. This requires an explicit discussion, and possibly
     * customer communication, if this is intended.
     */
    it("loads the expected set of vectors", () => {
      expect(vectors.map((vector) => vector.name).sort()).toEqual(["v1-grants-v2", "v2-grants-v1"]);
    });

    testVectors.eachEmergencyAccess()(
      "%s: the grantee decrypts the grantor's vault with the recorded key",
      async (_name, vector) => {
        const { id, grantor, granteeClient } = await seededGrant(
          harness,
          vector,
          ServerType.view,
          ServerStatus.recoveryApproved,
        );

        const result = await granteeClient.view_vault_items(id);

        expect(result.successes).toHaveLength(grantor.ciphers().length);
        validateCiphers(result, grantor.seed, []);
      },
      UNLOCK_TIMEOUT,
    );

    testVectors.eachEmergencyAccess()(
      "%s: the grantee takes over, and the grantor unlocks with the new password",
      async (_name, vector) => {
        const { id, grantor, granteeClient } = await seededGrant(
          harness,
          vector,
          ServerType.takeover,
          ServerStatus.recoveryApproved,
        );

        await granteeClient.takeover(id, NEW_PASSWORD, grantor.email);

        // The old password no longer unlocks: the server now serves the unlock data the grantee set.
        const stale = harness.newClientEmulator();
        await stale.login(grantor.email);
        await expect(stale.unlock(grantor.vector.account.password)).rejects.toBeDefined();

        // The new one unlocks to the same user key, so the vault decrypts unchanged.
        const client = harness.newClientEmulator();
        await client.login(grantor.email);
        await client.unlock(NEW_PASSWORD);
        await validateVault(client, grantor.seed, []);
      },
      UNLOCK_TIMEOUT,
    );
  });

  describe("lifecycle", () => {
    testVectors.eachEmergencyAccess()(
      "%s: invite, accept, confirm, initiate, approve, then view",
      async (_name, vector) => {
        const grantor = harness.server.seedUserTestVector(vector.grantorVector);
        const grantee = harness.server.seedUserTestVector(vector.granteeVector);
        const grantorClient = await emergencyAccessOf(harness, grantor);
        const granteeClient = await emergencyAccessOf(harness, grantee);

        // 1. The grantor invites; the grantee accepts with the token the invite email carries
        await grantorClient.invite(grantee.email, EmergencyAccessType.View, WAIT_TIME_DAYS);
        const invite = harness.server.inviteEmailFor(grantee.email);
        const id = asEmergencyAccessId(invite.id);
        await granteeClient.accept(id, invite.token);

        const [trusted] = await grantorClient.list_trusted();
        expect(trusted).toMatchObject({
          id,
          granteeId: grantee.userId,
          email: grantee.email,
          type: EmergencyAccessType.View,
          status: EmergencyAccessStatus.Accepted,
          waitTimeDays: WAIT_TIME_DAYS,
        });

        // 2. The grantor seals their user key to the grantee. A real client reads the public key
        //    from `GET /users/{id}/public-key` and has the user verify its fingerprint first.
        const granteePublicKey = asB64(harness.server.getUser(grantee.email).publicKey);
        await grantorClient.confirm(id, granteePublicKey);

        // 3. The grantee requests access and the grantor approves it
        await granteeClient.initiate(id);
        expect((await granteeClient.list_granted())[0].status).toBe(
          EmergencyAccessStatus.RecoveryInitiated,
        );
        await grantorClient.approve(id);

        const [granted] = await granteeClient.list_granted();
        expect(granted).toMatchObject({
          id,
          grantorId: grantor.userId,
          email: grantor.email,
          status: EmergencyAccessStatus.RecoveryApproved,
        });

        // 4. The key sealed this run, not the recorded one, decrypts the grantor's vault
        const result = await granteeClient.view_vault_items(id);
        expect(result.successes).toHaveLength(grantor.ciphers().length);
        validateCiphers(result, grantor.seed, []);
      },
      UNLOCK_TIMEOUT,
    );

    it(
      "reject returns an approved grant to confirmed and revokes the view",
      async () => {
        const { id, grantorClient, granteeClient } = await seededGrant(
          harness,
          vectors[0],
          ServerType.view,
          ServerStatus.recoveryApproved,
        );

        await grantorClient.reject(id);

        expect((await grantorClient.get(id)).status).toBe(EmergencyAccessStatus.Confirmed);
        await expect(granteeClient.view_vault_items(id)).rejects.toBeDefined();
      },
      UNLOCK_TIMEOUT,
    );

    it(
      "update changes what the grantee is granted",
      async () => {
        const { id, grantorClient, granteeClient } = await seededGrant(
          harness,
          vectors[0],
          ServerType.view,
          ServerStatus.confirmed,
        );

        await grantorClient.update(id, EmergencyAccessType.Takeover, WAIT_TIME_DAYS);

        const [granted] = await granteeClient.list_granted();
        expect(granted.type).toBe(EmergencyAccessType.Takeover);
        expect(granted.waitTimeDays).toBe(WAIT_TIME_DAYS);
      },
      UNLOCK_TIMEOUT,
    );

    it(
      "delete by the grantee removes the grant from both sides",
      async () => {
        const { id, grantorClient, granteeClient } = await seededGrant(
          harness,
          vectors[0],
          ServerType.view,
          ServerStatus.confirmed,
        );

        await granteeClient.delete(id);

        expect(await granteeClient.list_granted()).toEqual([]);
        expect(await grantorClient.list_trusted()).toEqual([]);
      },
      UNLOCK_TIMEOUT,
    );

    it(
      "reinvite is refused once the invite was accepted",
      async () => {
        const { id, grantorClient } = await seededGrant(
          harness,
          vectors[0],
          ServerType.view,
          ServerStatus.accepted,
        );

        await expect(grantorClient.reinvite(id)).rejects.toBeDefined();
      },
      UNLOCK_TIMEOUT,
    );

    it(
      "a view grant does not allow a takeover",
      async () => {
        const { id, grantor, granteeClient } = await seededGrant(
          harness,
          vectors[0],
          ServerType.view,
          ServerStatus.recoveryApproved,
        );
        const unlockBefore = harness.server.getUser(grantor.email).masterPasswordUnlock;

        await expect(granteeClient.takeover(id, NEW_PASSWORD, grantor.email)).rejects.toBeDefined();
        expect(harness.server.getUser(grantor.email).masterPasswordUnlock).toBe(unlockBefore);
      },
      UNLOCK_TIMEOUT,
    );

    it(
      "an approved takeover reads the grantor's policies",
      async () => {
        const { id, granteeClient } = await seededGrant(
          harness,
          vectors[0],
          ServerType.takeover,
          ServerStatus.recoveryApproved,
        );

        expect(await granteeClient.get_grantor_policies(id)).toEqual([]);
      },
      UNLOCK_TIMEOUT,
    );
  });
});
