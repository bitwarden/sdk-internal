// Low-level assertions on the three organization subjects: the shape of the committed vectors, the
// invite-link wire protocol, and the sealed open-org invite context.
//
// The invite-link suite is the reason most of this file reads request bodies. An invite is a bundle of
// five sealed envelopes that the admin posts and the invitee later redeems, and almost every property
// worth asserting — which envelopes are present, that the secret never leaves the client, that
// confirming and merely accepting post different fields — is only visible on the wire. It runs against
// its own route table (`invite-link-server.ts`) rather than the model server, so route sequences are
// asserted directly here.

import { ClientSettings, CryptoClient, PasswordManagerClient } from "@bitwarden/sdk-internal";

import { HttpMock, installHttpMock } from "../http-mock";
import {
  TEST_INVITE,
  TEST_INVITE_NO_CONFIRMATION,
  TEST_INVITE_SECRET,
  TEST_ORGANIZATION_ID,
} from "../org-fixtures";
import {
  makeOrgAccountClient,
  makeOrgInitializedClient,
  makePasswordManagerClient,
  makeStateBridge,
} from "../utils";
import { CREATION_DATE, LINK_CODE, LINK_ID, ROUTES, inviteLinkRoutes } from "./invite-link-server";
import { memberVector, organizationCases } from "./vault-support";

describe("organization test vectors", () => {
  describe.each(organizationCases)("%s", (_name, vector) => {
    it("covers both the keyed and keyless organization cipher shapes", () => {
      // The two are decrypted along different paths: a keyed item's fields sit under a per-item key
      // that the organization key unwraps, a keyless item's sit directly under the organization key.
      // Both must work, so the vault is expected to carry one of each.
      const keyed = vector.vault.ciphers.filter((cipher) => cipher.keys.cipherKey !== null);
      const keyless = vector.vault.ciphers.filter((cipher) => cipher.keys.cipherKey === null);

      expect(keyed.length).toBeGreaterThan(0);
      expect(keyless.length).toBeGreaterThan(0);
    });

    it("records an organization key whose id matches the key material", () => {
      const keyId = CryptoClient.get_key_id_for_symmetric_key(
        Buffer.from(vector.organizationKey, "base64"),
      );

      if (vector.organizationKeyId === null) {
        // A V1 `Aes256CbcHmac` organization key carries no key id at all.
        expect(keyId).toBeUndefined();
      } else {
        expect(keyId === undefined ? undefined : Buffer.from(keyId).toString("hex")).toBe(
          vector.organizationKeyId,
        );
      }
    });

    it("seals the organization key to every member, agreeing with that member's own vector", () => {
      expect(vector.members.length).toBeGreaterThan(0);

      for (const [index, member] of vector.members.entries()) {
        const user = memberVector(vector, index);
        // `organizationKeys` is keyed by the plain id string; `OrganizationId` is branded, so it
        // needs widening before it can index the record.
        const fromUserVector = (user.account.organizationKeys ?? {})[String(vector.organizationId)];

        // The two files are generated independently; if they ever disagree about the sealed key, one
        // of them is stale and the member below would fail to unseal it.
        expect(fromUserVector?.toString()).toBe(member.organizationKeySealedToMember.toString());
      }
    });

    it("never blob-encrypts organization ciphers, even when a member is a V2 account", () => {
      // Blob encryption is individual-vault only until PM-32430; `should_use_blob_encryption`
      // returns false whenever `organization_id` is set, regardless of the member's security version.
      for (const cipher of vector.vault.ciphers) {
        expect(cipher.blobEncrypted).toBe(false);
      }

      // Without a V2 member the assertion above would hold trivially.
      const securityVersions = vector.members.map(
        (_member, index) => memberVector(vector, index).account.securityVersion,
      );
      expect(Math.max(...securityVersions)).toBeGreaterThanOrEqual(2);
    });

    it("enrolls at least one member in account recovery", () => {
      const enrolled = vector.members.filter((member) => member.accountRecoveryKey != null);
      expect(enrolled.length).toBeGreaterThan(0);

      // The enrolled member's user key sealed to the organization's public key, which is what lets an
      // admin recover them. Unsealing it needs the organization private key, so it is asserted for
      // shape here and exercised on the Rust side.
      for (const member of enrolled) {
        expect(member.accountRecoveryKey!.toString()).toMatch(/^\d+\./);
      }
    });
  });
});

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
    await invitee.invite_link().accept_and_optionally_confirm(
      TEST_ORGANIZATION_ID,
      // The response model types `code` loosely; this parameter takes a plain string.
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

const SAMPLE_INPUT = {
  organizationId: "1bc9ac1e-f5aa-45f2-94bf-b181009709b8",
  inviteLinkCode: "abcd1234efgh5678",
  inviteSecret: "raw-invite-secret-material-base64url",
};

describe("open org invite registration seal/unseal", () => {
  it("seal_open_org_invite_data returns a non-empty sealedData and paired highEntropySecret", async () => {
    const client = makePasswordManagerClient(makeStateBridge());

    const sealed = client.auth().registration().seal_open_org_invite_data(SAMPLE_INPUT);

    expect(sealed.sealedData).not.toEqual("");
    expect(sealed.highEntropySecret).not.toEqual("");
  });

  it("unseal_open_org_invite_data recovers the plaintext invite context with fields intact", () => {
    const client = makePasswordManagerClient(makeStateBridge());
    const registration = client.auth().registration();

    const sealed = registration.seal_open_org_invite_data(SAMPLE_INPUT);
    const unsealed = registration.unseal_open_org_invite_data(sealed);

    expect(unsealed.organizationId).toEqual(SAMPLE_INPUT.organizationId);
    expect(unsealed.inviteLinkCode).toEqual(SAMPLE_INPUT.inviteLinkCode);
    expect(unsealed.inviteSecret).toEqual(SAMPLE_INPUT.inviteSecret);
  });

  it("two independent seals produce different highEntropySecret values (per-registration randomness)", () => {
    const client = makePasswordManagerClient(makeStateBridge());
    const registration = client.auth().registration();

    const first = registration.seal_open_org_invite_data(SAMPLE_INPUT);
    const second = registration.seal_open_org_invite_data(SAMPLE_INPUT);

    expect(first.highEntropySecret).not.toEqual(second.highEntropySecret);
    expect(first.sealedData).not.toEqual(second.sealedData);
  });

  it("the sealedData serializes as base64url that crosses the FFI boundary intact", async () => {
    const client = makePasswordManagerClient(makeStateBridge());

    const sealed = client.auth().registration().seal_open_org_invite_data(SAMPLE_INPUT);

    // Wire-format sanity: sealedData must round-trip through Node's native "base64url"
    // encoding (available since Node 16) without drift.
    const sealedStr = sealed.sealedData as unknown as string;
    expect(sealedStr).not.toEqual("");
    const reencoded = Buffer.from(sealedStr, "base64url").toString("base64url");
    expect(reencoded).toEqual(sealedStr);
  });
});
