import { isOrganizationKeyIdBackfillError, OrganizationUserType } from "@bitwarden/sdk-internal";

import { LoginMethod, type ClientEmulator } from "../../client-emulator/client-emulator";
import type { OrganizationEntity } from "../../server-emulator/entities";
import { testHarness, type TestHarness } from "../../test-harness";
import { fromUuid } from "../type-assertion-helpers";
import { toSeedOrganization } from "../../vectors/load";
import { testVectors } from "../../vectors/test-vectors";
import { rejection } from "../utils";

/** An organization whose key id the server has not recorded. */
const ORGANIZATION_VECTOR = testVectors.organizations.get("example-org");
const ORGANIZATION_ID = ORGANIZATION_VECTOR.organizationId;

/** A member of {@link ORGANIZATION_VECTOR} who logs in with a master password. */
const MEMBER_VECTOR = testVectors.users.withMasterPassword().get("v1-pbkdf2-password");

/** Key ids travel as a lowercase hex encoding of 16 bytes. */
const KEY_ID_PATTERN = /^[0-9a-f]{32}$/;

const TIMEOUT = 60_000;

describe("organization key id backfill", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  });

  afterEach(() => harness.restore());

  /** Seeds the member and the organization, with the member in `type`. */
  function seedMember(type: OrganizationUserType): void {
    const { email } = harness.server.seedUserTestVector(MEMBER_VECTOR);

    const organization = toSeedOrganization(ORGANIZATION_VECTOR);
    harness.server.seedOrganization({
      ...organization,
      // The other members are not seeded, so only this one is kept.
      members: organization.members
        .filter((member) => member.userEmail === email)
        .map((member) => ({ ...member, type })),
    });
  }

  /** Logs the member in and unlocks, which puts the organization key in the key store. */
  async function loginMember(): Promise<ClientEmulator> {
    const client = harness.newClientEmulator();
    await client.login(
      MEMBER_VECTOR.account.email,
      LoginMethod.Password,
      MEMBER_VECTOR.account.password,
    );
    await client.unlock(MEMBER_VECTOR.account.password);

    return client;
  }

  /** The organization row the server holds. */
  function serverOrganization(): OrganizationEntity {
    const organization = harness.server.db.organizations.get(fromUuid(ORGANIZATION_ID));
    if (organization === undefined) {
      throw new Error("the organization is not seeded");
    }

    return organization;
  }

  describe("organization_key_ids_needing_backfill", () => {
    it(
      "lists an organization the account owns when the server holds no key id",
      async () => {
        // 1. Log in as an Owner of an organization the server holds no key id for
        seedMember(OrganizationUserType.Owner);
        const client = await loginMember();

        // 2. Verify the organization is outstanding
        expect(
          await client
            .getPasswordManagerClient()
            .organization_crypto_management()
            .organization_key_ids_needing_backfill(),
        ).toEqual([ORGANIZATION_ID]);
      },
      TIMEOUT,
    );

    it(
      "is empty once the sync carries the key id",
      async () => {
        // 1. Log in as an Owner and backfill the key id
        seedMember(OrganizationUserType.Owner);
        const client = await loginMember();
        await client
          .getPasswordManagerClient()
          .organization_crypto_management()
          .organization_key_id_backfill();

        // 2. Log in and unlock on a new client
        const returning = await loginMember();

        // 3. Verify the sync stored the server's key id, and nothing is outstanding
        const [organization] = returning.local.organizations.dump();
        expect(organization?.details.keyId).toEqual(serverOrganization().organizationKeyId);
        expect(
          await returning
            .getPasswordManagerClient()
            .organization_crypto_management()
            .organization_key_ids_needing_backfill(),
        ).toEqual([]);
      },
      TIMEOUT,
    );

    it(
      "is empty for a member who is not an Owner or Admin",
      async () => {
        // 1. Log in as a User, who holds the organization key but cannot record its id
        seedMember(OrganizationUserType.User);
        const client = await loginMember();

        // 2. Verify nothing is outstanding
        expect(
          await client
            .getPasswordManagerClient()
            .organization_crypto_management()
            .organization_key_ids_needing_backfill(),
        ).toEqual([]);
      },
      TIMEOUT,
    );
  });

  describe("organization_key_id_backfill", () => {
    it(
      "records the organization key id on the server",
      async () => {
        // 1. Log in as an Owner of an organization the server holds no key id for
        seedMember(OrganizationUserType.Owner);
        const client = await loginMember();

        // 2. Backfill the key id
        await client
          .getPasswordManagerClient()
          .organization_crypto_management()
          .organization_key_id_backfill();

        // 3. Verify the server recorded a key id
        const recorded = serverOrganization().organizationKeyId;
        expect(recorded).toMatch(KEY_ID_PATTERN);

        // 4. Verify a new client that only syncs stores the same key id
        const returning = harness.newClientEmulator();
        await returning.login(
          MEMBER_VECTOR.account.email,
          LoginMethod.Password,
          MEMBER_VECTOR.account.password,
        );
        const [organization] = returning.local.organizations.dump();
        expect(organization?.details.keyId).toEqual(recorded);
      },
      TIMEOUT,
    );

    it(
      "changes nothing when the server already holds a different key id",
      async () => {
        // 1. Log in as an Owner. The sync carries no key id
        seedMember(OrganizationUserType.Owner);
        const client = await loginMember();

        // 2. Another key id reaches the server after the sync
        const other = "00".repeat(16);
        serverOrganization().organizationKeyId = other;

        // 3. Backfill the key id
        const error = await rejection(
          client
            .getPasswordManagerClient()
            .organization_crypto_management()
            .organization_key_id_backfill(),
          isOrganizationKeyIdBackfillError,
        );

        // 4. Verify the request reached the server and was refused there
        expect(error.variant).toBe("Api");

        // 5. Verify the server kept its key id
        expect(serverOrganization().organizationKeyId).toEqual(other);
      },
      TIMEOUT,
    );
  });
});
