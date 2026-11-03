import { ClientSettings, PasswordManagerClient } from "@bitwarden/sdk-internal";

import { HttpMock, MockReply, installHttpMock } from "../../server-emulator/http-mock";
import { TEST_ORGANIZATION_ID } from "../org-fixtures";
import { makePasswordManagerClient, makeStateBridge } from "../utils";

// Nothing listens here; every request is served by the fetch mock. A concrete host keeps the
// SDK's request URLs parseable and makes an unmocked route fail loudly rather than escape to
// the network.
const SETTINGS: ClientSettings = {
  apiUrl: "http://localhost:4000",
  identityUrl: "http://localhost:4000/identity",
};

const ORG = TEST_ORGANIZATION_ID as unknown as string;
const GET_MINI = `GET /organizations/${ORG}/domain/mini`;
/** The full endpoint requires Manage SSO; calling it without that permission logs the user out. */
const GET_FULL = `GET /organizations/${ORG}/domain`;

interface MiniDomain {
  domainName?: string | null;
  verifiedDate?: string | null;
}

/** The list the mini domains endpoint returns. */
function miniList(rows: MiniDomain[]): MockReply {
  return {
    json: {
      object: "list",
      data: rows.map((row) => ({ object: "organizationDomainMini", ...row })),
      continuationToken: null,
    },
  };
}

// The Rust unit tests cover the filtering in detail. These tests exist to prove the FFI-specific
// concerns: the client is reachable, it calls the endpoint a Manage Users member is allowed to
// call, the domains cross the boundary as plain strings, and failures surface as typed errors.
describe("organization domains client", () => {
  // Every command here is a plain API call with no crypto, so the client needs no unlock.
  let client: PasswordManagerClient;
  let mock: HttpMock;

  beforeAll(() => {
    client = makePasswordManagerClient(makeStateBridge(), SETTINGS);
  });

  afterEach(() => {
    expect(mock.unmatched.map((request) => request.route)).toEqual([]);
    mock.restore();
  });

  describe("get_verified_domains", () => {
    it("fetches the mini domains and returns only the verified domain names", async () => {
      mock = installHttpMock({
        [GET_MINI]: () =>
          miniList([
            { domainName: "verified.com", verifiedDate: "2026-09-15T00:00:00Z" },
            { domainName: "unverified.com", verifiedDate: null },
            { domainName: "also-verified.com", verifiedDate: "2026-09-16T00:00:00Z" },
          ]),
      });

      const domains = await client
        .organization_domains()
        .get_verified_domains(TEST_ORGANIZATION_ID);

      expect(mock.routes()).toEqual([GET_MINI]);
      // Must not fall through to the Manage SSO-only endpoint.
      expect(mock.called(GET_FULL)).toBe(false);

      expect(domains).toEqual(["verified.com", "also-verified.com"]);
    });

    it("returns an empty array when the organization has no verified domains", async () => {
      mock = installHttpMock({
        [GET_MINI]: () => miniList([{ domainName: "unverified.com", verifiedDate: null }]),
      });

      const domains = await client
        .organization_domains()
        .get_verified_domains(TEST_ORGANIZATION_ID);

      expect(domains).toEqual([]);
    });

    it("rejects with a typed error when the server refuses the request", async () => {
      mock = installHttpMock({
        [GET_MINI]: () => ({ status: 404, json: { message: "Resource not found." } }),
      });

      await expect(
        client.organization_domains().get_verified_domains(TEST_ORGANIZATION_ID),
      ).rejects.toMatchObject({ name: "OrganizationDomainsError", variant: "Api" });
    });

    it("rejects with a typed error when a verified domain has no name", async () => {
      mock = installHttpMock({
        [GET_MINI]: () => miniList([{ domainName: null, verifiedDate: "2026-09-15T00:00:00Z" }]),
      });

      await expect(
        client.organization_domains().get_verified_domains(TEST_ORGANIZATION_ID),
      ).rejects.toMatchObject({ name: "OrganizationDomainsError", variant: "MissingField" });
    });
  });
});
