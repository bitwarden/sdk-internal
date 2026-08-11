import {
  PasswordManagerClient,
  PolicyView,
  OrganizationUserPolicyContext,
  PolicyType,
  OrganizationUserType,
  OrganizationUserStatusType,
  Uuid,
} from "@bitwarden/sdk-internal";

import { makePasswordManagerClient, makeStateBridge } from "../utils";

// `filter_by_type` is a pure function with no crypto or network, so the client needs no unlock.
// The filtering *behavior* is covered comprehensively by the crate's Rust unit tests
// (`PolicyClient::filter_by_type`). These integration tests exist only to prove FFI-specific concerns.

const uuid = (s: string) => s as unknown as Uuid;

const POLICY_ID = uuid("1c4d9d5a-0000-4000-8000-000000000000");
const ORG_A = uuid("1c4d9d5a-0000-4000-8000-00000000000a");

interface PolicyViewOptions {
  id?: Uuid;
  enabled?: boolean;
  data?: string;
  revisionDate?: string;
}

function policyView(
  organizationId: Uuid,
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

function orgContext(id: Uuid, options: OrgContextOptions = {}): OrganizationUserPolicyContext {
  return {
    id,
    role: options.role ?? OrganizationUserType.User,
    status: options.status ?? OrganizationUserStatusType.Confirmed,
    enabled: options.enabled ?? true,
    usePolicies: options.usePolicies ?? true,
    isProviderUser: options.isProviderUser ?? false,
  };
}

describe("PolicyClient.filter_by_type", () => {
  let client: PasswordManagerClient;

  beforeAll(() => {
    client = makePasswordManagerClient(makeStateBridge());
  });

  const filter = (
    policies: PolicyView[],
    orgs: OrganizationUserPolicyContext[],
    type: PolicyType,
  ) => client.policies().filter_by_type(policies, orgs, type);

  it("is callable and returns a matching policy across the FFI boundary", () => {
    const result = filter(
      [policyView(ORG_A, PolicyType.MasterPassword)],
      [orgContext(ORG_A)],
      PolicyType.MasterPassword,
    );

    expect(result).toHaveLength(1);
    expect(result[0].type).toBe(PolicyType.MasterPassword);
  });

  describe("FFI fidelity", () => {
    it("round-trips every PolicyView field unchanged", () => {
      const id = uuid("1c4d9d5a-0000-4000-8000-0000000000ff");
      const data = JSON.stringify({ minComplexity: 3, minLength: 12 });
      const revisionDate = "2024-01-01T00:00:00.000Z";

      const result = filter(
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
      const result = filter(
        [policyView(ORG_A, PolicyType.MasterPassword)],
        [orgContext(ORG_A)],
        PolicyType.MasterPassword,
      );

      expect(result).toHaveLength(1);
      expect(result[0].data).toBeUndefined();
      expect(result[0].revisionDate).toBeUndefined();
    });
  });
});
