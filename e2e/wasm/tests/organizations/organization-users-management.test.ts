import { isOrganizationUsersManagementError } from "@bitwarden/sdk-internal";

import { OrganizationRole, PendingMemberStatus } from "../../server-emulator/entities";
import type { SeededOrganization } from "../../server-emulator/server-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import { rejection } from "../utils";

const TIMEOUT = 120_000;

const ORG_VECTOR = testVectors.organizations.get("example-org");

/** Members of {@link ORG_VECTOR}, by user-vector name. */
const ADMIN = "v1-pbkdf2-password";
const USER = "v1-argon2id-password";

const NOT_STAGED = "User is not staged.";
const NOT_INVITED = "User invalid.";

// The Rust unit tests cover the mapping in detail. These tests prove the ids cross the boundary as
// plain strings, and the per-member outcome, including the absence of an error, survives the trip
// back.
describe("organization users management client", () => {
  let harness: TestHarness;
  let organization: SeededOrganization;

  beforeEach(() => {
    harness = testHarness();
    organization = harness.server.seedOrganizationTestVector(ORG_VECTOR, {
      [ADMIN]: OrganizationRole.Admin,
    });
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /** Status of the pending member `id`, as the server holds it. */
  function statusOf(id: unknown): PendingMemberStatus | undefined {
    return harness.server
      .organization(organization.organizationId)
      .pendingMembers.find((member) => member.id === id)?.status;
  }

  it(
    "sends invites to staged members, and reports the rest",
    async () => {
      // 1. One member is staged, one already invited
      const staged = harness.server.addPendingMember(
        organization.organizationId,
        "staged@example.com",
        PendingMemberStatus.Staged,
      );
      const invited = harness.server.addPendingMember(
        organization.organizationId,
        "invited@example.com",
        PendingMemberStatus.Invited,
      );

      // 2. An admin sends invites to both
      const admin = await harness.newUnlockedClient(organization.members[ADMIN]);
      const results = await admin
        .getPasswordManagerClient()
        .organization_users_management()
        .send_staged_invites(organization.organizationId, [staged, invited]);

      // 3. Verify the outcome per member, and that the staged member is now invited
      expect(results.map((result) => [result.id, result.error])).toEqual([
        [staged, undefined],
        [invited, NOT_STAGED],
      ]);
      expect(statusOf(staged)).toBe(PendingMemberStatus.Invited);
    },
    TIMEOUT,
  );

  it(
    "refuses to send invites for a member who cannot manage users",
    async () => {
      // 1. A plain member sends an invite to a staged member
      const staged = harness.server.addPendingMember(
        organization.organizationId,
        "staged@example.com",
        PendingMemberStatus.Staged,
      );
      const user = await harness.newUnlockedClient(organization.members[USER]);
      const error = await rejection(
        user
          .getPasswordManagerClient()
          .organization_users_management()
          .send_staged_invites(organization.organizationId, [staged]),
        isOrganizationUsersManagementError,
      );

      // 2. Verify the request is refused, and the member is still staged
      expect(error.variant).toBe("Api");
      expect(statusOf(staged)).toBe(PendingMemberStatus.Staged);
    },
    TIMEOUT,
  );

  it(
    "reinvites invited members in bulk, and reports the rest",
    async () => {
      // 1. One member is invited, one only staged
      const invited = harness.server.addPendingMember(
        organization.organizationId,
        "invited@example.com",
        PendingMemberStatus.Invited,
      );
      const staged = harness.server.addPendingMember(
        organization.organizationId,
        "staged@example.com",
        PendingMemberStatus.Staged,
      );

      // 2. An admin reinvites both
      const admin = await harness.newUnlockedClient(organization.members[ADMIN]);
      const results = await admin
        .getPasswordManagerClient()
        .organization_users_management()
        .bulk_reinvite(organization.organizationId, [invited, staged]);

      // 3. Verify the outcome per member, and that reinviting staged nobody
      expect(results.map((result) => [result.id, result.error])).toEqual([
        [invited, undefined],
        [staged, NOT_INVITED],
      ]);
      expect(statusOf(staged)).toBe(PendingMemberStatus.Staged);
    },
    TIMEOUT,
  );

  it(
    "reinvites a single invited member",
    async () => {
      // 1. An invited member
      const invited = harness.server.addPendingMember(
        organization.organizationId,
        "invited@example.com",
        PendingMemberStatus.Invited,
      );

      // 2. Verify an admin reinvites them
      const admin = await harness.newUnlockedClient(organization.members[ADMIN]);
      await admin
        .getPasswordManagerClient()
        .organization_users_management()
        .reinvite(organization.organizationId, invited);
    },
    TIMEOUT,
  );

  it(
    "refuses to reinvite a single member who was never invited",
    async () => {
      // 1. A staged member
      const staged = harness.server.addPendingMember(
        organization.organizationId,
        "staged@example.com",
        PendingMemberStatus.Staged,
      );

      // 2. Verify an admin's reinvite is refused
      const admin = await harness.newUnlockedClient(organization.members[ADMIN]);
      const error = await rejection(
        admin
          .getPasswordManagerClient()
          .organization_users_management()
          .reinvite(organization.organizationId, staged),
        isOrganizationUsersManagementError,
      );
      expect(error.variant).toBe("Api");
    },
    TIMEOUT,
  );
});
