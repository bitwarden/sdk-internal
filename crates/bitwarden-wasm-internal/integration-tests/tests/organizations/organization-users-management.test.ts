import { ClientSettings, OrganizationUserId, PasswordManagerClient } from "@bitwarden/sdk-internal";

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
const SEND_INVITE = `POST /organizations/${ORG}/users/send-invite`;
const REINVITE = `POST /organizations/${ORG}/users/reinvite`;
const reinviteOne = (id: OrganizationUserId) =>
  `POST /organizations/${ORG}/users/${id as unknown as string}/reinvite`;

const memberId = (s: string) => s as unknown as OrganizationUserId;
const MEMBER_A = memberId("1c4d9d5a-0000-4000-8000-00000000000a");
const MEMBER_B = memberId("1c4d9d5a-0000-4000-8000-00000000000b");

/** The list the bulk member endpoints return; the server reports success as an empty error. */
function bulkList(rows: { id: OrganizationUserId; error: string }[]): MockReply {
  return {
    json: {
      object: "list",
      data: rows.map((row) => ({ object: "organizationUserBulkResponseModel", ...row })),
      continuationToken: null,
    },
  };
}

// The Rust unit tests cover the mapping in detail. These tests exist to prove the FFI-specific
// concerns: the client is reachable, the ids cross the boundary as plain strings, and the
// per-member outcome — including the absence of an error — survives the trip back.
describe("organization users management client", () => {
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

  describe("send_staged_invites", () => {
    it("posts the member ids and returns the outcome per member", async () => {
      mock = installHttpMock({
        [SEND_INVITE]: () =>
          bulkList([
            { id: MEMBER_A, error: "" },
            { id: MEMBER_B, error: "User is not staged." },
          ]),
      });

      const results = await client
        .organization_users_management()
        .send_staged_invites(TEST_ORGANIZATION_ID, [MEMBER_A, MEMBER_B]);

      expect(mock.routes()).toEqual([SEND_INVITE]);
      expect(mock.bodyFor(SEND_INVITE)).toEqual({ ids: [MEMBER_A, MEMBER_B] });

      expect(results).toHaveLength(2);
      expect(results[0].id).toBe(MEMBER_A);
      expect(results[0].error).toBeUndefined();
      expect(results[1].id).toBe(MEMBER_B);
      expect(results[1].error).toBe("User is not staged.");
    });

    it("rejects with a typed error when the server refuses the batch", async () => {
      mock = installHttpMock({
        [SEND_INVITE]: () => ({
          status: 400,
          json: { message: "Seat limit has been reached." },
        }),
      });

      await expect(
        client
          .organization_users_management()
          .send_staged_invites(TEST_ORGANIZATION_ID, [MEMBER_A]),
      ).rejects.toMatchObject({ name: "OrganizationUsersManagementError", variant: "Api" });
    });
  });

  describe("bulk_reinvite", () => {
    it("posts the member ids to the reinvite endpoint and returns the outcome per member", async () => {
      mock = installHttpMock({
        [REINVITE]: () =>
          bulkList([
            { id: MEMBER_A, error: "" },
            { id: MEMBER_B, error: "User invalid." },
          ]),
      });

      const results = await client
        .organization_users_management()
        .bulk_reinvite(TEST_ORGANIZATION_ID, [MEMBER_A, MEMBER_B]);

      expect(mock.routes()).toEqual([REINVITE]);
      // Reinviting must not fall through to the staged-invite endpoint.
      expect(mock.called(SEND_INVITE)).toBe(false);
      expect(mock.bodyFor(REINVITE)).toEqual({ ids: [MEMBER_A, MEMBER_B] });

      expect(results).toHaveLength(2);
      expect(results[0].id).toBe(MEMBER_A);
      expect(results[0].error).toBeUndefined();
      expect(results[1].id).toBe(MEMBER_B);
      expect(results[1].error).toBe("User invalid.");
    });
  });

  describe("reinvite", () => {
    it("posts to the member's reinvite endpoint with no body and resolves", async () => {
      mock = installHttpMock({ [reinviteOne(MEMBER_A)]: () => ({}) });

      await expect(
        client.organization_users_management().reinvite(TEST_ORGANIZATION_ID, MEMBER_A),
      ).resolves.toBeUndefined();

      expect(mock.routes()).toEqual([reinviteOne(MEMBER_A)]);
      expect(mock.requests[0].body).toBe("");
    });

    it("rejects with a typed error when the member cannot be reinvited", async () => {
      mock = installHttpMock({
        [reinviteOne(MEMBER_A)]: () => ({ status: 400, json: { message: "User invalid." } }),
      });

      await expect(
        client.organization_users_management().reinvite(TEST_ORGANIZATION_ID, MEMBER_A),
      ).rejects.toMatchObject({ name: "OrganizationUsersManagementError", variant: "Api" });
    });
  });
});
