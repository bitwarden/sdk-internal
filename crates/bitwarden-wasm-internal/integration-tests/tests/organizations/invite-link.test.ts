import { ClientSettings, PasswordManagerClient } from "@bitwarden/sdk-internal";

import { HttpMock, installHttpMock } from "../http-mock";
import {
  TEST_INVITE,
  TEST_INVITE_NO_CONFIRMATION,
  TEST_INVITE_SECRET,
  TEST_ORGANIZATION_ID,
} from "../org-fixtures";
import { makeOrgAccountClient, makeOrgInitializedClient, makeStateBridge } from "../utils";
import { CREATION_DATE, LINK_CODE, LINK_ID, ROUTES, inviteLinkRoutes } from "./invite-link-server";

// Nothing listens here; every request is served by the fetch mock. A concrete host keeps the
// SDK's request URLs parseable and makes an unmocked route fail loudly rather than escape to
// the network.
const SETTINGS: ClientSettings = {
  apiUrl: "http://localhost:4000",
  identityUrl: "http://localhost:4000/identity",
};

const COLLECTION_NAME = "My Items";
/** A base64url-encoded, 32-byte invite secret. */
const SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

describe("invite link client", () => {
  // Unlocking runs 600k PBKDF2 iterations, so both clients are built once. They hold no per-test
  // state — the mock is what varies between tests.
  let admin: PasswordManagerClient;
  let invitee: PasswordManagerClient;
  let mock: HttpMock;

  beforeAll(async () => {
    admin = await makeOrgInitializedClient(makeStateBridge(), SETTINGS);
    invitee = await makeOrgAccountClient(makeStateBridge(), SETTINGS);
  });

  afterEach(() => {
    expect(mock.unmatched.map((request) => request.route)).toEqual([]);
    mock.restore();
  });

  describe("create_invite_link", () => {
    it("posts a new invite and returns the persisted link", async () => {
      mock = installHttpMock(inviteLinkRoutes());

      const link = await admin
        .invite_link()
        .create_invite_link(TEST_ORGANIZATION_ID, ["example.com", "test.com"], true);

      expect(mock.routes()).toEqual([ROUTES.privateKey, ROUTES.create]);

      const posted = mock.bodyFor(ROUTES.create);
      expect(Object.keys(posted).sort()).toEqual([
        "allowedDomains",
        "invite",
        "supportsConfirmation",
      ]);
      expect(posted.allowedDomains).toEqual(["example.com", "test.com"]);
      expect(posted.supportsConfirmation).toBe(true);
      // New invites carry all five sealed envelopes.
      expect(Object.keys(JSON.parse(posted.invite)).sort()).toEqual([
        "invite_key_sealed_invite_data_cek",
        "invite_key_sealed_organization_key",
        "invite_secret_sealed_invite_key",
        "organization_key_sealed_invite_key",
        "sealed_invite_data",
      ]);

      expect(link.id).toBe(LINK_ID);
      expect(link.code).toBe(LINK_CODE);
      expect(link.organizationId).toBe(TEST_ORGANIZATION_ID);
      expect(link.allowedDomains).toEqual(["example.com", "test.com"]);
      expect(link.supportsConfirmation).toBe(true);
      expect(new Date(link.creationDate).toISOString()).toBe(new Date(CREATION_DATE).toISOString());
      // An invite crosses the boundary as a tagged string, not as a serialized struct.
      expect(typeof link.invite).toBe("string");
      expect(link.invite).toBe(posted.invite);
    });

    it("never sends the invite secret to the server", async () => {
      mock = installHttpMock(inviteLinkRoutes());
      const inviteLink = admin.invite_link();

      const link = await inviteLink.create_invite_link(TEST_ORGANIZATION_ID, [], true);
      const secret = inviteLink.get_invite_secret(TEST_ORGANIZATION_ID, link.invite);

      expect(secret).toMatch(SECRET_PATTERN);
      for (const request of mock.requests) {
        expect(request.body).not.toContain(secret);
      }
    });
  });

  describe("refresh_invite_link", () => {
    it("posts a new invite to the refresh endpoint", async () => {
      mock = installHttpMock(inviteLinkRoutes());

      const link = await admin.invite_link().refresh_invite_link(TEST_ORGANIZATION_ID, true);

      expect(mock.routes()).toEqual([ROUTES.privateKey, ROUTES.refresh]);
      // Refreshing must not fall through to the create endpoint.
      expect(mock.called(ROUTES.create)).toBe(false);

      const posted = mock.bodyFor(ROUTES.refresh);
      expect(Object.keys(posted).sort()).toEqual(["invite", "supportsConfirmation"]);
      expect(posted.supportsConfirmation).toBe(true);
      expect(link.invite).toBe(posted.invite);
    });

    it("replaces the invite and its secret", async () => {
      mock = installHttpMock(inviteLinkRoutes());
      const inviteLink = admin.invite_link();

      const created = await inviteLink.create_invite_link(TEST_ORGANIZATION_ID, [], true);
      const refreshed = await inviteLink.refresh_invite_link(TEST_ORGANIZATION_ID, true);

      expect(refreshed.invite).not.toBe(created.invite);
      expect(inviteLink.get_invite_secret(TEST_ORGANIZATION_ID, refreshed.invite)).not.toBe(
        inviteLink.get_invite_secret(TEST_ORGANIZATION_ID, created.invite),
      );
    });
  });

  describe("get_invite_secret", () => {
    it("recovers the invite secret from an invite passed as a parameter", () => {
      mock = installHttpMock(inviteLinkRoutes());

      const secret = admin.invite_link().get_invite_secret(TEST_ORGANIZATION_ID, TEST_INVITE);

      expect(secret).toEqual(TEST_INVITE_SECRET);
      expect(mock.requests).toEqual([]);
    });

    it("recovers the same secret from an invite with confirmation disabled", () => {
      mock = installHttpMock(inviteLinkRoutes());

      const secret = admin
        .invite_link()
        .get_invite_secret(TEST_ORGANIZATION_ID, TEST_INVITE_NO_CONFIRMATION);

      expect(secret).toEqual(TEST_INVITE_SECRET);
    });
  });

  describe("accept_and_optionally_confirm", () => {
    it("self-confirms when the invite supports confirmation", async () => {
      mock = installHttpMock(inviteLinkRoutes());

      await invitee
        .invite_link()
        .accept_and_optionally_confirm(
          TEST_ORGANIZATION_ID,
          LINK_CODE,
          TEST_INVITE_SECRET,
          COLLECTION_NAME,
          false,
        );

      expect(mock.routes()).toEqual([ROUTES.getInvite, ROUTES.confirm]);
      expect(mock.bodyFor(ROUTES.getInvite)).toEqual({
        code: LINK_CODE,
        organizationId: TEST_ORGANIZATION_ID,
      });

      const posted = mock.bodyFor(ROUTES.confirm);
      expect(Object.keys(posted).sort()).toEqual([
        "code",
        "defaultUserCollectionName",
        "orgUserKey",
        "organizationId",
      ]);
      expect(posted.organizationId).toBe(TEST_ORGANIZATION_ID);
      expect(posted.code).toBe(LINK_CODE);
      // An `UnsignedSharedKey`: the organization key encapsulated to the invitee's public key.
      expect(posted.orgUserKey).toMatch(/^\d+\./);
      expect(posted.defaultUserCollectionName).not.toContain(COLLECTION_NAME);
      // Not enrolling means no recovery key is sent at all.
      expect(posted).not.toHaveProperty("resetPasswordKey");
    });

    it("enrolls into account recovery when asked", async () => {
      mock = installHttpMock(inviteLinkRoutes());

      await invitee
        .invite_link()
        .accept_and_optionally_confirm(
          TEST_ORGANIZATION_ID,
          LINK_CODE,
          TEST_INVITE_SECRET,
          COLLECTION_NAME,
          true,
        );

      expect(mock.routes()).toEqual([ROUTES.publicKey, ROUTES.getInvite, ROUTES.confirm]);

      const posted = mock.bodyFor(ROUTES.confirm);
      expect(typeof posted.resetPasswordKey).toBe("string");
      // The user key encapsulated to the recovery key, distinct from the org key to the user.
      expect(posted.resetPasswordKey).not.toBe(posted.orgUserKey);
    });

    it("only accepts when the invite does not support confirmation", async () => {
      mock = installHttpMock(
        inviteLinkRoutes({ invite: TEST_INVITE_NO_CONFIRMATION as unknown as string }),
      );

      await invitee
        .invite_link()
        .accept_and_optionally_confirm(
          TEST_ORGANIZATION_ID,
          LINK_CODE,
          TEST_INVITE_SECRET,
          COLLECTION_NAME,
          false,
        );

      expect(mock.routes()).toEqual([ROUTES.getInvite, ROUTES.accept]);
      expect(mock.called(ROUTES.confirm)).toBe(false);

      // Without confirmation the invitee cannot reach the organization key, so it must not send
      // one — an admin confirms them out of band instead.
      const posted = mock.bodyFor(ROUTES.accept);
      expect(Object.keys(posted).sort()).toEqual(["code", "organizationId"]);
      expect(posted).not.toHaveProperty("orgUserKey");
      expect(posted).not.toHaveProperty("defaultUserCollectionName");
    });

    it("enrolls into account recovery while accepting without confirmation", async () => {
      mock = installHttpMock(
        inviteLinkRoutes({ invite: TEST_INVITE_NO_CONFIRMATION as unknown as string }),
      );

      await invitee
        .invite_link()
        .accept_and_optionally_confirm(
          TEST_ORGANIZATION_ID,
          LINK_CODE,
          TEST_INVITE_SECRET,
          COLLECTION_NAME,
          true,
        );

      expect(mock.routes()).toEqual([ROUTES.publicKey, ROUTES.getInvite, ROUTES.accept]);

      const posted = mock.bodyFor(ROUTES.accept);
      expect(Object.keys(posted).sort()).toEqual(["code", "organizationId", "resetPasswordKey"]);
      expect(typeof posted.resetPasswordKey).toBe("string");
      expect(posted).not.toHaveProperty("orgUserKey");
    });
  });

  it("round-trips an invite from an admin creating a link to an invitee redeeming it", async () => {
    // Whatever the admin posts is what the server hands back to the invitee.
    let persisted: string | undefined;
    mock = installHttpMock(
      inviteLinkRoutes({
        onCreate: (invite) => {
          persisted = invite;
        },
        invite: () => persisted!,
      }),
    );

    const adminInviteLink = admin.invite_link();
    const link = await adminInviteLink.create_invite_link(
      TEST_ORGANIZATION_ID,
      ["example.com"],
      true,
    );
    const secret = adminInviteLink.get_invite_secret(TEST_ORGANIZATION_ID, link.invite);

    expect(persisted).toBe(link.invite);

    // The invitee holds no organization key; everything they send is derived from the secret.
    await invitee
      .invite_link()
      .accept_and_optionally_confirm(
        TEST_ORGANIZATION_ID,
        String(link.code),
        secret,
        COLLECTION_NAME,
        true,
      );

    expect(mock.routes()).toEqual([
      ROUTES.privateKey,
      ROUTES.create,
      ROUTES.publicKey,
      ROUTES.getInvite,
      ROUTES.confirm,
    ]);

    const confirmed = mock.bodyFor(ROUTES.confirm);
    expect(confirmed.code).toBe(link.code);
    expect(confirmed.organizationId).toBe(link.organizationId);
    expect(typeof confirmed.orgUserKey).toBe("string");
    expect(typeof confirmed.resetPasswordKey).toBe("string");

    // The whole point of the invite secret: it lives in the link, never on the wire.
    for (const request of mock.requests) {
      expect(request.body).not.toContain(secret);
    }
  });
});
