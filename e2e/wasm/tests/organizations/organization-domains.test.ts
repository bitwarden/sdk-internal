import { isOrganizationDomainsError } from "@bitwarden/sdk-internal";

import { OrganizationRole } from "../../server-emulator/entities";
import type { SeededOrganization } from "../../server-emulator/server-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import { rejection } from "../utils";

const TIMEOUT = 120_000;

const ORG_VECTOR = testVectors.organizations.get("example-org");

/** Members of {@link ORG_VECTOR}, by user-vector name. */
const ADMIN = "v1-pbkdf2-password";
const USER = "v1-argon2id-password";

// The Rust unit tests cover the filtering in detail. These tests prove the client calls the
// endpoint a Manage Users member may call, and the domains cross the boundary as plain strings.
// The full domains endpoint is not modeled: it needs Manage SSO, and a call to it would answer 501.
describe("organization domains client", () => {
  let harness: TestHarness;
  let organization: SeededOrganization;

  beforeEach(() => {
    harness = testHarness();
    organization = harness.server.seedOrganizationTestVector(ORG_VECTOR, {
      [ADMIN]: OrganizationRole.Admin,
    });
  }, TIMEOUT);

  afterEach(() => harness.restore());

  it(
    "lists only the verified domains to a member who manages users",
    async () => {
      // 1. The organization claims three domains and verifies two
      harness.server.claimDomain(organization.organizationId, "verified.com", true);
      harness.server.claimDomain(organization.organizationId, "unverified.com", false);
      harness.server.claimDomain(organization.organizationId, "also-verified.com", true);

      // 2. Verify an admin sees the verified ones
      const admin = await harness.newUnlockedClient(organization.members[ADMIN]);
      const domains = await admin
        .getPasswordManagerClient()
        .organization_domains()
        .get_verified_domains(organization.organizationId);
      expect(domains).toEqual(["verified.com", "also-verified.com"]);
    },
    TIMEOUT,
  );

  it(
    "lists nothing when no domain is verified",
    async () => {
      // 1. The organization claims a domain it has not verified
      harness.server.claimDomain(organization.organizationId, "unverified.com", false);

      // 2. Verify an admin sees none
      const admin = await harness.newUnlockedClient(organization.members[ADMIN]);
      const domains = await admin
        .getPasswordManagerClient()
        .organization_domains()
        .get_verified_domains(organization.organizationId);
      expect(domains).toEqual([]);
    },
    TIMEOUT,
  );

  it(
    "refuses a member who cannot manage users",
    async () => {
      // 1. A plain member asks for the domains
      harness.server.claimDomain(organization.organizationId, "verified.com", true);
      const user = await harness.newUnlockedClient(organization.members[USER]);

      // 2. Verify the request is refused
      const error = await rejection(
        user
          .getPasswordManagerClient()
          .organization_domains()
          .get_verified_domains(organization.organizationId),
        isOrganizationDomainsError,
      );
      expect(error.variant).toBe("Api");
    },
    TIMEOUT,
  );
});
