import { EmergencyAccessStatus, EmergencyAccessType } from "@bitwarden/sdk-internal";

import { validateCiphers, validateVault } from "../../client-emulator/validate";
import {
  EmergencyAccessStatus as ServerStatus,
  EmergencyAccessType as ServerType,
} from "../../server-emulator/dto";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import { asB64, asEmergencyAccessId } from "../type-assertion-helpers";

const UNLOCK_TIMEOUT = 120_000;
const WAIT_TIME_DAYS = 7;
const NEW_PASSWORD = "a new master password set by the grantee";
const V1_GRANTS_V2 = "v1-grants-v2";

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
      expect(
        testVectors.emergencyAccess
          .all()
          .map((vector) => vector.name)
          .sort(),
      ).toEqual(["v1-grants-v2", "v2-grants-v1"]);
    });

    testVectors.emergencyAccess.each(
      "$name: the grantee decrypts the grantor's vault with the recorded key",
      async (vector) => {
        const users = testVectors.users.withMasterPassword();
        const seeded = harness.server.seedEmergencyAccessTestVector(vector, {
          type: ServerType.view,
          status: ServerStatus.recoveryApproved,
        });
        const id = asEmergencyAccessId(seeded.id);

        const grantee = harness.newClientEmulator();
        await grantee.login(seeded.grantee.email);
        await grantee.unlock(users.get(vector.granteeVectorName).account.password);
        const granteeClient = grantee.getPasswordManagerClient().emergency_access();

        const result = await granteeClient.view_vault_items(id);

        expect(result.successes).toHaveLength(seeded.grantor.ciphers().length);
        validateCiphers(result, seeded.grantor.seed, []);
      },
      UNLOCK_TIMEOUT,
    );

    testVectors.emergencyAccess.each(
      "$name: the grantee takes over, and the grantor unlocks with the new password",
      async (vector) => {
        const users = testVectors.users.withMasterPassword();
        const seeded = harness.server.seedEmergencyAccessTestVector(vector, {
          type: ServerType.takeover,
          status: ServerStatus.recoveryApproved,
        });
        const id = asEmergencyAccessId(seeded.id);

        const grantee = harness.newClientEmulator();
        await grantee.login(seeded.grantee.email);
        await grantee.unlock(users.get(vector.granteeVectorName).account.password);
        const granteeClient = grantee.getPasswordManagerClient().emergency_access();

        await granteeClient.takeover(id, NEW_PASSWORD, seeded.grantor.email);

        // The old password no longer unlocks: the server now serves the unlock data the grantee set.
        const stale = harness.newClientEmulator();
        await stale.login(seeded.grantor.email);
        await expect(
          stale.unlock(users.get(vector.grantorVectorName).account.password),
        ).rejects.toBeDefined();

        // The new one unlocks to the same user key, so the vault decrypts unchanged.
        const client = harness.newClientEmulator();
        await client.login(seeded.grantor.email);
        await client.unlock(NEW_PASSWORD);
        await validateVault(client, seeded.grantor.seed, []);
      },
      UNLOCK_TIMEOUT,
    );
  });

  describe("lifecycle", () => {
    testVectors.emergencyAccess.each(
      "$name: invite, accept, confirm, initiate, approve, then view",
      async (vector) => {
        const users = testVectors.users.withMasterPassword();
        const grantorVector = users.get(vector.grantorVectorName);
        const granteeVector = users.get(vector.granteeVectorName);
        const grantor = harness.server.seedUserTestVector(grantorVector);
        const grantee = harness.server.seedUserTestVector(granteeVector);

        const grantorEmulator = harness.newClientEmulator();
        await grantorEmulator.login(grantor.email);
        await grantorEmulator.unlock(grantorVector.account.password);
        const grantorClient = grantorEmulator.getPasswordManagerClient().emergency_access();

        const granteeEmulator = harness.newClientEmulator();
        await granteeEmulator.login(grantee.email);
        await granteeEmulator.unlock(granteeVector.account.password);
        const granteeClient = granteeEmulator.getPasswordManagerClient().emergency_access();

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
        const vector = testVectors.emergencyAccess.get(V1_GRANTS_V2);
        const users = testVectors.users.withMasterPassword();
        const seeded = harness.server.seedEmergencyAccessTestVector(vector, {
          type: ServerType.view,
          status: ServerStatus.recoveryApproved,
        });
        const id = asEmergencyAccessId(seeded.id);

        const grantor = harness.newClientEmulator();
        await grantor.login(seeded.grantor.email);
        await grantor.unlock(users.get(vector.grantorVectorName).account.password);
        const grantorClient = grantor.getPasswordManagerClient().emergency_access();

        const grantee = harness.newClientEmulator();
        await grantee.login(seeded.grantee.email);
        await grantee.unlock(users.get(vector.granteeVectorName).account.password);
        const granteeClient = grantee.getPasswordManagerClient().emergency_access();

        await grantorClient.reject(id);

        expect((await grantorClient.get(id)).status).toBe(EmergencyAccessStatus.Confirmed);
        await expect(granteeClient.view_vault_items(id)).rejects.toBeDefined();
      },
      UNLOCK_TIMEOUT,
    );

    it(
      "update changes what the grantee is granted",
      async () => {
        const vector = testVectors.emergencyAccess.get(V1_GRANTS_V2);
        const users = testVectors.users.withMasterPassword();
        const seeded = harness.server.seedEmergencyAccessTestVector(vector, {
          type: ServerType.view,
          status: ServerStatus.confirmed,
        });
        const id = asEmergencyAccessId(seeded.id);

        const grantor = harness.newClientEmulator();
        await grantor.login(seeded.grantor.email);
        await grantor.unlock(users.get(vector.grantorVectorName).account.password);
        const grantorClient = grantor.getPasswordManagerClient().emergency_access();

        const grantee = harness.newClientEmulator();
        await grantee.login(seeded.grantee.email);
        await grantee.unlock(users.get(vector.granteeVectorName).account.password);
        const granteeClient = grantee.getPasswordManagerClient().emergency_access();

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
        const vector = testVectors.emergencyAccess.get(V1_GRANTS_V2);
        const users = testVectors.users.withMasterPassword();
        const seeded = harness.server.seedEmergencyAccessTestVector(vector, {
          type: ServerType.view,
          status: ServerStatus.confirmed,
        });
        const id = asEmergencyAccessId(seeded.id);

        const grantor = harness.newClientEmulator();
        await grantor.login(seeded.grantor.email);
        await grantor.unlock(users.get(vector.grantorVectorName).account.password);
        const grantorClient = grantor.getPasswordManagerClient().emergency_access();

        const grantee = harness.newClientEmulator();
        await grantee.login(seeded.grantee.email);
        await grantee.unlock(users.get(vector.granteeVectorName).account.password);
        const granteeClient = grantee.getPasswordManagerClient().emergency_access();

        await granteeClient.delete(id);

        expect(await granteeClient.list_granted()).toEqual([]);
        expect(await grantorClient.list_trusted()).toEqual([]);
      },
      UNLOCK_TIMEOUT,
    );

    it(
      "reinvite is refused once the invite was accepted",
      async () => {
        const vector = testVectors.emergencyAccess.get(V1_GRANTS_V2);
        const users = testVectors.users.withMasterPassword();
        const seeded = harness.server.seedEmergencyAccessTestVector(vector, {
          type: ServerType.view,
          status: ServerStatus.accepted,
        });
        const id = asEmergencyAccessId(seeded.id);

        const grantor = harness.newClientEmulator();
        await grantor.login(seeded.grantor.email);
        await grantor.unlock(users.get(vector.grantorVectorName).account.password);
        const grantorClient = grantor.getPasswordManagerClient().emergency_access();

        await expect(grantorClient.reinvite(id)).rejects.toBeDefined();
      },
      UNLOCK_TIMEOUT,
    );

    it(
      "a view grant does not allow a takeover",
      async () => {
        const vector = testVectors.emergencyAccess.get(V1_GRANTS_V2);
        const users = testVectors.users.withMasterPassword();
        const seeded = harness.server.seedEmergencyAccessTestVector(vector, {
          type: ServerType.view,
          status: ServerStatus.recoveryApproved,
        });
        const id = asEmergencyAccessId(seeded.id);

        const grantee = harness.newClientEmulator();
        await grantee.login(seeded.grantee.email);
        await grantee.unlock(users.get(vector.granteeVectorName).account.password);
        const granteeClient = grantee.getPasswordManagerClient().emergency_access();

        const unlockBefore = harness.server.getUser(seeded.grantor.email).masterPasswordUnlock;

        await expect(
          granteeClient.takeover(id, NEW_PASSWORD, seeded.grantor.email),
        ).rejects.toBeDefined();
        expect(harness.server.getUser(seeded.grantor.email).masterPasswordUnlock).toBe(
          unlockBefore,
        );
      },
      UNLOCK_TIMEOUT,
    );

    it(
      "an approved takeover reads the grantor's policies",
      async () => {
        const vector = testVectors.emergencyAccess.get(V1_GRANTS_V2);
        const users = testVectors.users.withMasterPassword();
        const seeded = harness.server.seedEmergencyAccessTestVector(vector, {
          type: ServerType.takeover,
          status: ServerStatus.recoveryApproved,
        });
        const id = asEmergencyAccessId(seeded.id);

        const grantee = harness.newClientEmulator();
        await grantee.login(seeded.grantee.email);
        await grantee.unlock(users.get(vector.granteeVectorName).account.password);
        const granteeClient = grantee.getPasswordManagerClient().emergency_access();

        expect(await granteeClient.get_grantor_policies(id)).toEqual([]);
      },
      UNLOCK_TIMEOUT,
    );
  });
});
