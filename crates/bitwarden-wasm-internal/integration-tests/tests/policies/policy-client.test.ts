import {
  PasswordManagerClient,
  PolicyView,
  OrganizationUserPolicyContext,
  PolicyType,
  OrganizationUserType,
  OrganizationUserStatusType,
  OrganizationId,
  Uuid,
} from "@bitwarden/sdk-internal";

import { asOrganizationId } from "../type-assertion-helpers";
import { makePasswordManagerClient, makeStateBridge } from "../utils";

// `filter_by_type` is a pure function with no crypto or network, so the client needs no unlock.
// The filtering *behavior* is covered comprehensively by the crate's Rust unit tests
// (`PolicyClient::filter_by_type`). These integration tests exist only to prove FFI-specific concerns.

const uuid = (s: string) => s as unknown as Uuid;

const POLICY_ID = uuid("1c4d9d5a-0000-4000-8000-000000000000");
const ORG_A = asOrganizationId("1c4d9d5a-0000-4000-8000-00000000000a");
const ORG_B = asOrganizationId("1c4d9d5a-0000-4000-8000-00000000000b");

interface PolicyViewOptions {
  id?: Uuid;
  enabled?: boolean;
  data?: string;
  revisionDate?: string;
}

function policyView(
  organizationId: OrganizationId,
  type: PolicyType,
  options: PolicyViewOptions = {},
): PolicyView {
  return {
    id: options.id ?? POLICY_ID,
    organizationId,
    type,
    data: options.data,
    enabled: options.enabled ?? true,
    // The generated type is `DateTime<Utc>`, but at runtime it is an ISO string.
    revisionDate: options.revisionDate as unknown as PolicyView["revisionDate"],
  };
}

interface OrgContextOptions {
  role?: OrganizationUserType;
  status?: OrganizationUserStatusType;
  enabled?: boolean;
  usePolicies?: boolean;
  isProviderUser?: boolean;
}

function orgContext(
  id: OrganizationId,
  options: OrgContextOptions = {},
): OrganizationUserPolicyContext {
  return {
    id,
    role: options.role ?? OrganizationUserType.User,
    status: options.status ?? OrganizationUserStatusType.Confirmed,
    enabled: options.enabled ?? true,
    usePolicies: options.usePolicies ?? true,
    isProviderUser: options.isProviderUser ?? false,
  };
}

describe("PolicyClient", () => {
  describe("filter_by_type", () => {
    let client: PasswordManagerClient;

    beforeAll(() => {
      client = makePasswordManagerClient(makeStateBridge());
    });

    it("is callable and returns a matching policy across the FFI boundary", () => {
      const result = client
        .policies()
        .filter_by_type(
          [policyView(ORG_A, PolicyType.MasterPassword)],
          [orgContext(ORG_A)],
          PolicyType.MasterPassword,
        );

      expect(result).toHaveLength(1);
      expect(result[0].type).toBe(PolicyType.MasterPassword);
    });

    it("round-trips every PolicyView field unchanged", () => {
      const id = uuid("1c4d9d5a-0000-4000-8000-0000000000ff");
      const data = JSON.stringify({ minComplexity: 3, minLength: 12 });
      const revisionDate = "2024-01-01T00:00:00.000Z";

      const result = client
        .policies()
        .filter_by_type(
          [policyView(ORG_A, PolicyType.MasterPassword, { id, data, revisionDate })],
          [orgContext(ORG_A)],
          PolicyType.MasterPassword,
        );

      expect(result).toHaveLength(1);
      const view = result[0];
      expect(view.id).toBe(id);
      expect(view.organizationId).toBe(ORG_A);
      expect(view.type).toBe(PolicyType.MasterPassword);
      // `data` is an opaque JSON string and must cross unparsed.
      expect(view.data).toBe(data);
      expect(view.enabled).toBe(true);
      expect(new Date(view.revisionDate as unknown as string).toISOString()).toBe(revisionDate);
    });

    it("maps omitted optional fields to undefined, not null", () => {
      const result = client
        .policies()
        .filter_by_type(
          [policyView(ORG_A, PolicyType.MasterPassword)],
          [orgContext(ORG_A)],
          PolicyType.MasterPassword,
        );

      expect(result).toHaveLength(1);
      expect(result[0].data).toBeUndefined();
      expect(result[0].revisionDate).toBeUndefined();
    });
  });

  // `get_enforced` / `get_all_enforced` are the new type-erased enforcement interfaces. As with
  // `filter_by_type`, these tests prove the FFI round trip rather than re-proving the enforcement
  // logic (which is covered by the crate's Rust unit tests). The load-bearing new shape is the
  // `EnforcedPolicyErased` struct and the internally-tagged `PolicyDataType` union: unit variants
  // cross as `{ type: "..." }`, and the data variant flattens `MasterPasswordPolicyResponse` beside
  // the `type` discriminant.

  describe("get_enforced", () => {
    let client: PasswordManagerClient;

    beforeAll(() => {
      client = makePasswordManagerClient(makeStateBridge());
    });

    it("round-trips a data-carrying decision (internally-tagged union with flattened data)", () => {
      const data = JSON.stringify({ minComplexity: 3, minLength: 12 });

      const result = client
        .policies()
        .get_enforced(
          PolicyType.MasterPassword,
          ORG_A,
          [policyView(ORG_A, PolicyType.MasterPassword, { data })],
          [orgContext(ORG_A)],
        );

      expect(result.organizationId).toBe(ORG_A);
      expect(result.enforced).toBe(true);
      expect(result.data.type).toBe("masterPassword");
      // The `type` discriminant narrows to the flattened MasterPasswordPolicyResponse.
      if (result.data.type === "masterPassword") {
        expect(result.data.minComplexity).toBe(3);
        expect(result.data.minLength).toBe(12);
      }
    });

    it("round-trips a unit (dataless) variant as a tagged object", () => {
      const result = client
        .policies()
        .get_enforced(
          PolicyType.PasswordGenerator,
          ORG_A,
          [policyView(ORG_A, PolicyType.PasswordGenerator)],
          [orgContext(ORG_A)],
        );

      expect(result.enforced).toBe(true);
      expect(result.data.type).toBe("passwordGenerator");
    });

    it("returns a not-enforced default when no matching policy exists for the org", () => {
      const result = client
        .policies()
        .get_enforced(
          PolicyType.MasterPassword,
          ORG_B,
          [policyView(ORG_A, PolicyType.MasterPassword)],
          [orgContext(ORG_B)],
        );

      expect(result.organizationId).toBe(ORG_B);
      expect(result.enforced).toBe(false);
      expect(result.data.type).toBe("masterPassword");
    });

    it("does not enforce for a Revoked member and defaults the data (negative discriminant survives FFI)", () => {
      const data = JSON.stringify({ minComplexity: 3 });

      const result = client
        .policies()
        .get_enforced(
          PolicyType.MasterPassword,
          ORG_A,
          [policyView(ORG_A, PolicyType.MasterPassword, { data })],
          [orgContext(ORG_A, { status: OrganizationUserStatusType.Revoked })],
        );

      expect(result.enforced).toBe(false);
      // A non-enforced decision carries default data, so the parsed `minComplexity` is dropped.
      expect(result.data.type).toBe("masterPassword");
      if (result.data.type === "masterPassword") {
        expect(result.data.minComplexity).toBeUndefined();
      }
    });
  });

  describe("get_all_enforced", () => {
    let client: PasswordManagerClient;

    beforeAll(() => {
      client = makePasswordManagerClient(makeStateBridge());
    });

    it("returns one decision per matching view and excludes other types", () => {
      const result = client
        .policies()
        .get_all_enforced(
          PolicyType.MasterPassword,
          [
            policyView(ORG_A, PolicyType.MasterPassword),
            policyView(ORG_A, PolicyType.PasswordGenerator),
          ],
          [orgContext(ORG_A)],
        );

      expect(result).toHaveLength(1);
      expect(result[0].data.type).toBe("masterPassword");
      expect(result[0].enforced).toBe(true);
    });

    it("evaluates each organization independently", () => {
      // ORG_A's member is a subject User; ORG_B's member is an Owner, exempt from MaximumVaultTimeout.
      const result = client.policies().get_all_enforced(
        PolicyType.MaximumVaultTimeout,
        [
          policyView(ORG_A, PolicyType.MaximumVaultTimeout, {
            id: uuid("1c4d9d5a-0000-4000-8000-0000000000a1"),
          }),
          policyView(ORG_B, PolicyType.MaximumVaultTimeout, {
            id: uuid("1c4d9d5a-0000-4000-8000-0000000000b1"),
          }),
        ],
        [
          orgContext(ORG_A, { role: OrganizationUserType.User }),
          orgContext(ORG_B, { role: OrganizationUserType.Owner }),
        ],
      );

      expect(result).toHaveLength(2);
      const a = result.find((r) => r.organizationId === ORG_A);
      const b = result.find((r) => r.organizationId === ORG_B);
      expect(a?.enforced).toBe(true);
      expect(b?.enforced).toBe(false);
    });
  });
});
