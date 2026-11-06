import {
  CollectionType,
  InviteSecret,
  OrganizationInviteLinkView,
  PasswordManagerClient,
  isAcceptInviteLinkError,
  isInviteLinkError,
} from "@bitwarden/sdk-internal";

import { ClientEmulator, LoginMethod } from "../../client-emulator/client-emulator";
import { validateVault } from "../../client-emulator/validate";
import type {
  SeedAccount,
  SeedOrganizationOptions,
  SeededOrganization,
} from "../../server-emulator/server-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { toSeedAccount } from "../../vectors/load";
import { testVectors } from "../../vectors/test-vectors";
import { asEncString } from "../type-assertion-helpers";
import { rejection } from "../utils";

const UNLOCK_TIMEOUT = 120_000;

const ORGANIZATION = "example-org";
/** A confirmed member of {@link ORGANIZATION}, made its owner. */
const ADMIN = "v1-pbkdf2-password";
/**
 * The invitee where the account does not matter. It is outside {@link ORGANIZATION}, and its low
 * iteration count keeps unlocking it cheap.
 */
const INVITEE = "v1-pbkdf2-min-iterations";
/**
 * Every account that can redeem a link: those with a master password, since the others cannot log
 * in by password here, and outside {@link ORGANIZATION}, since a member cannot join it again.
 */
const INVITEES = testVectors.users
  .withMasterPassword()
  .except(
    ...testVectors.organizations.get(ORGANIZATION).members.map((member) => member.userVectorName),
  );
/** The domain every vector account's email is on. */
const VECTOR_DOMAIN = "test.bitwarden.com";

/** A plan with exactly as many seats as {@link ORGANIZATION} has members, so none is free. */
const FULL = testVectors.organizations.get(ORGANIZATION).members.length;

const COLLECTION_NAME = "My Items";
/** A base64url-encoded, 32-byte invite secret. */
const SECRET_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/** The four parts of a link's `#/join/{org}/{code}?key={secret}` URL fragment an invitee needs. */
function parseFragment(link: OrganizationInviteLinkView): {
  organizationId: string;
  code: string;
  secret: InviteSecret;
} {
  const match = /^#\/join\/([^/]+)\/([^?]+)\?key=(.+)$/.exec(link.urlFragment);
  if (match === null) {
    throw new Error(`unexpected URL fragment: ${link.urlFragment}`);
  }

  const [, organizationId, code, secret] = match;
  expect(secret).toMatch(SECRET_PATTERN);
  return { organizationId, code, secret: secret as unknown as InviteSecret };
}

/** The envelopes of a stored invite, which the server holds as an opaque JSON string. */
function envelopes(invite: string): Record<string, string | null> {
  return JSON.parse(invite);
}

describe("invite link client", () => {
  let harness: TestHarness;
  let org: SeededOrganization;
  let organizationId: SeededOrganization["organizationId"];

  beforeEach(() => {
    harness = testHarness();
  });

  afterEach(() => {
    harness.restore();
  });

  /** Seeds the organization, with {@link ADMIN} as its owner, and `invitee`'s account. */
  function seed(options: Omit<SeedOrganizationOptions, "roles"> = {}, invitee = INVITEE): void {
    org = harness.server.seedOrganizationTestVector(testVectors.organizations.get(ORGANIZATION), {
      ...options,
      roles: { [ADMIN]: "owner" },
    });
    organizationId = org.organizationId;
    harness.server.seedUserTestVector(testVectors.users.get(invitee));
  }

  function passwordOf(vectorName: string): string {
    return testVectors.users.withMasterPassword().get(vectorName).account.password;
  }

  /** Logs `vectorName`'s account in from a new client and unlocks it. */
  async function signIn(vectorName: string): Promise<ClientEmulator> {
    const vector = testVectors.users.withMasterPassword().get(vectorName);
    const client = harness.newClientEmulator();
    await client.login(vector.account.email, LoginMethod.Password, vector.account.password);
    await client.unlock(vector.account.password);
    return client;
  }

  async function sdkFor(vectorName: string): Promise<PasswordManagerClient> {
    return (await signIn(vectorName)).getPasswordManagerClient();
  }

  /** The admin's link, created with confirmation on unless `supportsConfirmation` says otherwise. */
  async function createLink(
    admin: PasswordManagerClient,
    supportsConfirmation = true,
    allowedDomains = [VECTOR_DOMAIN],
  ): Promise<OrganizationInviteLinkView> {
    return await admin
      .invite_link()
      .admin()
      .create(organizationId, allowedDomains, supportsConfirmation);
  }

  /** Redeems `link` as `invitee`, with everything taken from the link as a real invitee would. */
  async function redeem(
    invitee: PasswordManagerClient,
    link: OrganizationInviteLinkView,
    enrollIntoAccountRecovery = false,
  ): Promise<void> {
    const { code, secret } = parseFragment(link);
    await invitee
      .invite_link()
      .user()
      .accept_and_optionally_confirm(
        organizationId,
        code,
        secret,
        COLLECTION_NAME,
        enrollIntoAccountRecovery,
      );
  }

  /** `invitee`'s membership as the server holds it, if any. */
  function inviteeMembership(invitee = INVITEE) {
    const user = harness.server.getUser(testVectors.users.get(invitee).account.email);
    return harness.server
      .getOrganization(organizationId)
      .members.find((member) => member.userId === user.userId);
  }

  /** Fails if any request body the emulator saw carries `plaintext`. */
  function expectNeverSent(plaintext: InviteSecret | string): void {
    expect(harness.requests.length).toBeGreaterThan(0);
    for (const request of harness.requests) {
      expect(request.body).not.toContain(String(plaintext));
    }
  }

  /** The body of the one request the invitee made to `route`. */
  function postedTo(route: string): Record<string, unknown> {
    const sent = harness.requests.filter((request) => request.route === route);
    expect(sent).toHaveLength(1);
    return sent[0].json();
  }

  /** Decrypts the invitee's default collection name, as stored on its membership, as `admin`. */
  function defaultCollectionName(admin: PasswordManagerClient, encrypted: string): string {
    return admin
      .vault()
      .collections()
      .decrypt({
        id: undefined,
        organizationId,
        name: asEncString(encrypted),
        externalId: undefined,
        hidePasswords: false,
        readOnly: false,
        manage: false,
        defaultUserCollectionEmail: undefined,
        type: CollectionType.DefaultUserCollection,
      }).name;
  }

  describe("admin", () => {
    describe("create", () => {
      it(
        "stores a sealed invite under a server-generated code",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);

          // 1. Create a link, with domains the server has to sanitize
          const link = await createLink(admin, true, ["Test.Bitwarden.com", "  other.com "]);

          // 2. Verify the server stored it, with the domains sanitized
          const stored = harness.server.inviteLinkFor(organizationId);
          expect(stored).toBeDefined();
          expect(link.id).toBe(stored!.id);
          expect(link.organizationId).toBe(organizationId);
          expect(link.supportsConfirmation).toBe(true);
          expect(stored!.allowedDomains).toEqual(["test.bitwarden.com", "other.com"]);
          expect(link.allowedDomains).toEqual(stored!.allowedDomains);

          // 3. Verify the link carries the code the server generated, not one the client chose
          const fragment = parseFragment(link);
          expect(fragment.organizationId).toBe(String(organizationId));
          expect(fragment.code).toBe(stored!.code);

          // 4. Verify the invite itself never crosses the boundary; the client only gets the link
          //    to share
          expect(link).not.toHaveProperty("invite");
          expect(Object.keys(envelopes(stored!.invite)).sort()).toEqual([
            "invite_key_sealed_invite_data_cek",
            "invite_key_sealed_organization_key",
            "invite_secret_sealed_invite_key",
            "organization_key_sealed_invite_key",
            "sealed_invite_data",
          ]);
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "never sends the invite secret to the server",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);

          // 1. Create a link
          const link = await createLink(admin);

          // 2. Verify no request carried its secret
          expectNeverSent(parseFragment(link).secret);
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "refuses a second link for the same organization",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);
          const first = await createLink(admin);

          // 1. Create a second link
          const error = await rejection(createLink(admin), isInviteLinkError);

          // 2. Verify the server refused it and kept the first
          expect(error.variant).toBe("Api");
          expect(harness.server.inviteLinkFor(organizationId)?.id).toBe(first.id);
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "refuses domains that are blank once sanitized",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);

          // 1. Create a link whose only domain is blank
          const error = await rejection(createLink(admin, true, ["   "]), isInviteLinkError);

          // 2. Verify the server refused it and stored nothing
          expect(error.variant).toBe("Api");
          expect(harness.server.inviteLinkFor(organizationId)).toBeUndefined();
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "refuses when the plan does not include invite links",
        async () => {
          seed({ useInviteLinks: false });
          const admin = await sdkFor(ADMIN);

          // 1. Create a link
          const error = await rejection(createLink(admin), isInviteLinkError);

          // 2. Verify the server refused it and stored nothing
          expect(error.variant).toBe("Api");
          expect(harness.server.inviteLinkFor(organizationId)).toBeUndefined();
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "refuses a member who is not an admin",
        async () => {
          seed();
          // The organization's other members are plain users.
          const member = await sdkFor("v1-argon2id-password");

          // 1. Create a link as a plain member
          const error = await rejection(createLink(member), isInviteLinkError);

          // 2. Verify the server refused it and stored nothing
          expect(error.variant).toBe("Api");
          expect(harness.server.inviteLinkFor(organizationId)).toBeUndefined();
        },
        UNLOCK_TIMEOUT,
      );
    });

    describe("get", () => {
      it(
        "answers nothing before a link exists, and the link after",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);

          // 1. Verify there is no link yet
          expect(await admin.invite_link().admin().get(organizationId)).toBeUndefined();

          // 2. Create one and fetch it
          const created = await createLink(admin);
          const fetched = await admin.invite_link().admin().get(organizationId);

          // 3. Verify it reads the same every time: the secret is recovered from the stored invite
          expect(fetched?.id).toBe(created.id);
          expect(fetched?.urlFragment).toBe(created.urlFragment);
        },
        UNLOCK_TIMEOUT,
      );
    });

    describe("refresh", () => {
      it(
        "replaces the code and secret, keeping the domains",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);
          const created = await createLink(admin);
          const before = harness.server.inviteLinkFor(organizationId)!;

          // 1. Refresh the link
          const refreshed = await admin.invite_link().admin().refresh(organizationId, true);

          // 2. Verify the server replaced it, keeping the domains
          const after = harness.server.inviteLinkFor(organizationId)!;
          expect(after.id).not.toBe(before.id);
          expect(after.code).not.toBe(before.code);
          expect(after.invite).not.toBe(before.invite);
          expect(after.allowedDomains).toEqual(before.allowedDomains);

          // 3. Verify the new link carries the new code and a new secret, which never left
          expect(parseFragment(refreshed).code).toBe(after.code);
          expect(parseFragment(refreshed).secret).not.toBe(parseFragment(created).secret);
          expectNeverSent(parseFragment(refreshed).secret);
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "stops links already handed out from working",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);
          const handedOut = await createLink(admin);
          const invitee = await signIn(INVITEE);

          // 1. Refresh the link, then redeem the one handed out before
          await admin.invite_link().admin().refresh(organizationId, true);
          const error = await rejection(
            redeem(invitee.getPasswordManagerClient(), handedOut),
            isAcceptInviteLinkError,
          );

          // 2. Verify it was refused
          expect(error.variant).toBe("LinkNotFound");

          // 3. Verify neither side moved
          expect(inviteeMembership()).toBeUndefined();
          await expectLocalVault(invitee, INVITEE, accountSeed(INVITEE));
        },
        UNLOCK_TIMEOUT,
      );
    });

    describe("update_confirmation", () => {
      it(
        "strips the organization-key envelope when disabling confirmation",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);
          const created = await createLink(admin, true);
          const before = harness.server.inviteLinkFor(organizationId)!;

          // 1. Disable confirmation
          const link = await admin.invite_link().admin().update_confirmation(organizationId, false);

          // 2. Verify the server holds the link without confirmation
          const after = harness.server.inviteLinkFor(organizationId)!;
          expect(after.supportsConfirmation).toBe(false);
          expect(link.supportsConfirmation).toBe(false);

          // 3. Verify the envelope is nulled out rather than dropped, and the other four are
          //    untouched
          const original = envelopes(before.invite);
          const stripped = envelopes(after.invite);
          expect(original.invite_key_sealed_organization_key).not.toBeNull();
          expect(stripped.invite_key_sealed_organization_key).toBeNull();
          for (const key of [
            "sealed_invite_data",
            "invite_key_sealed_invite_data_cek",
            "invite_secret_sealed_invite_key",
            "organization_key_sealed_invite_key",
          ]) {
            expect(stripped[key]).toBe(original[key]);
          }

          // 4. Verify links already handed out keep working: same code, same secret
          expect(after.code).toBe(before.code);
          expect(link.urlFragment).toBe(created.urlFragment);
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "re-seals the organization key when enabling confirmation",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);
          const created = await createLink(admin, false);
          const before = harness.server.inviteLinkFor(organizationId)!;

          // 1. Enable confirmation
          const link = await admin.invite_link().admin().update_confirmation(organizationId, true);

          // 2. Verify the server holds the link with confirmation
          const after = harness.server.inviteLinkFor(organizationId)!;
          expect(after.supportsConfirmation).toBe(true);
          expect(link.supportsConfirmation).toBe(true);

          // 3. Verify a fresh envelope appears where there was `null`. The invite key it wraps is
          //    unchanged, so `organization_key_sealed_invite_key` must not be rotated.
          expect(envelopes(before.invite).invite_key_sealed_organization_key).toBeNull();
          expect(envelopes(after.invite).invite_key_sealed_organization_key).toEqual(
            expect.any(String),
          );
          expect(envelopes(after.invite).organization_key_sealed_invite_key).toBe(
            envelopes(before.invite).organization_key_sealed_invite_key,
          );

          // 4. Verify the link reads the same, and its secret never left
          expect(link.urlFragment).toBe(created.urlFragment);
          expectNeverSent(parseFragment(link).secret);
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "lets an invitee redeem a link whose confirmation was turned off after creation",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);
          const handedOut = await createLink(admin, true);
          await admin.invite_link().admin().update_confirmation(organizationId, false);
          const invitee = await sdkFor(INVITEE);

          // 1. Redeem the link handed out before confirmation was turned off
          await redeem(invitee, handedOut);

          // 2. Verify the invitee could only accept, since confirmation was stripped
          expect(inviteeMembership()).toMatchObject({
            status: "accepted",
            organizationKeySealedToMember: null,
          });
        },
        UNLOCK_TIMEOUT,
      );
    });

    describe("update_allowed_domains", () => {
      it(
        "replaces the stored domains, sanitized",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);
          const created = await createLink(admin);

          // 1. Replace the domains, with ones the server has to sanitize
          const link = await admin
            .invite_link()
            .admin()
            .update_allowed_domains(organizationId, [" Example.COM ", "other.org"]);

          // 2. Verify the server stored them sanitized, and the link reads the same
          expect(harness.server.inviteLinkFor(organizationId)?.allowedDomains).toEqual([
            "example.com",
            "other.org",
          ]);
          expect(link.allowedDomains).toEqual(["example.com", "other.org"]);
          expect(link.urlFragment).toBe(created.urlFragment);
        },
        UNLOCK_TIMEOUT,
      );
    });

    describe("delete", () => {
      it(
        "removes the link, so it can no longer be redeemed",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);
          const handedOut = await createLink(admin);

          // 1. Delete the link
          await admin.invite_link().admin().delete(organizationId);

          // 2. Verify it is gone
          expect(harness.server.inviteLinkFor(organizationId)).toBeUndefined();
          expect(await admin.invite_link().admin().get(organizationId)).toBeUndefined();

          // 3. Redeem the link handed out before, and verify it was refused
          const invitee = await signIn(INVITEE);
          const error = await rejection(
            redeem(invitee.getPasswordManagerClient(), handedOut),
            isAcceptInviteLinkError,
          );
          expect(error.variant).toBe("LinkNotFound");

          // 4. Verify neither side moved
          expect(inviteeMembership()).toBeUndefined();
          await expectLocalVault(invitee, INVITEE, accountSeed(INVITEE));
        },
        UNLOCK_TIMEOUT,
      );
    });
  });

  describe("user", () => {
    describe("get_status", () => {
      it(
        "reports the organization and whether the link can be redeemed",
        async () => {
          seed();
          const link = await createLink(await sdkFor(ADMIN));
          const invitee = await sdkFor(INVITEE);

          // 1. Ask for the link's status
          const status = await invitee
            .invite_link()
            .user()
            .get_status(organizationId, parseFragment(link).code);

          // 2. Verify it reports the organization and that the link can be redeemed
          expect(status.organizationName).toBe(org.seed.name);
          expect(status.linksEnabled).toBe(true);
          expect(status.seatsAvailable).toBe(true);
          expect(status.supportsConfirmation).toBe(true);
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "reports no seats when the plan is full",
        async () => {
          seed({ seats: FULL });
          const link = await createLink(await sdkFor(ADMIN));
          const invitee = await sdkFor(INVITEE);

          // 1. Ask for the link's status
          const status = await invitee
            .invite_link()
            .user()
            .get_status(organizationId, parseFragment(link).code);

          // 2. Verify it reports no seats
          expect(status.seatsAvailable).toBe(false);
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "refuses a code that is not the link's",
        async () => {
          seed();
          await createLink(await sdkFor(ADMIN));
          const invitee = await sdkFor(INVITEE);

          // 1. Ask for the status of a code the server never generated
          const error = await rejection(
            invitee
              .invite_link()
              .user()
              .get_status(organizationId, "00000000-0000-4000-8000-000000000000"),
            isInviteLinkError,
          );

          // 2. Verify the server refused it
          expect(error.variant).toBe("Api");
        },
        UNLOCK_TIMEOUT,
      );
    });

    describe("is_email_allowed", () => {
      it(
        "answers by the link's allowed domains",
        async () => {
          seed();
          const link = await createLink(await sdkFor(ADMIN), true, ["example.com"]);
          const invitee = await sdkFor(INVITEE);
          const { code } = parseFragment(link);

          // 1. Verify an address on an allowed domain is allowed, and one on another is not
          const user = invitee.invite_link().user();
          expect(await user.is_email_allowed(organizationId, code, "someone@example.com")).toBe(
            true,
          );
          expect(await user.is_email_allowed(organizationId, code, "someone@other.com")).toBe(
            false,
          );
        },
        UNLOCK_TIMEOUT,
      );
    });

    describe("accept_and_optionally_confirm", () => {
      INVITEES.each(
        "$name self-confirms when the invite supports confirmation, gaining the organization",
        async (vector) => {
          seed({}, vector.name);
          const admin = await sdkFor(ADMIN);
          const link = await createLink(admin, true);
          const invitee = await signIn(vector.name);

          // 1. Redeem the link
          await redeem(invitee.getPasswordManagerClient(), link);

          // 2. Verify the server holds a confirmed membership, with no recovery key since the
          //    invitee did not enroll
          const member = inviteeMembership(vector.name);
          expect(member?.status).toBe("confirmed");
          expect(member?.organizationKeySealedToMember).toMatch(/^\d+\./);
          expect(member?.accountRecoveryKey).toBeUndefined();

          // 3. Verify the default collection name is organization data: it reaches the server
          //    encrypted with the organization key, so an admin opens it, and its plaintext never
          //    crosses the wire
          expect(member?.defaultCollectionName).toMatch(/^\d+\./);
          expect(defaultCollectionName(admin, member!.defaultCollectionName!)).toBe(
            COLLECTION_NAME,
          );
          expectNeverSent(COLLECTION_NAME);

          // 4. Verify local state: the key the invitee sealed to itself is the real organization
          //    key, so it decrypts the organization's ciphers alongside its own
          await expectLocalVault(invitee, vector.name, withOrganizationVault(vector.name));

          // 5. Verify server state: a fresh login does the same
          await expectServerVault(vector.name, withOrganizationVault(vector.name));
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "enrolls into account recovery when asked",
        async () => {
          seed();
          const link = await createLink(await sdkFor(ADMIN), true);
          const invitee = await sdkFor(INVITEE);

          // 1. Redeem the link, enrolling into account recovery
          await redeem(invitee, link, true);

          // 2. Verify the server holds a recovery key alongside the organization key
          const member = inviteeMembership();
          expect(member?.status).toBe("confirmed");
          expect(member?.accountRecoveryKey).toMatch(/^\d+\./);
          expect(member?.accountRecoveryKey).not.toBe(member?.organizationKeySealedToMember);
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "only accepts when the invite does not support confirmation",
        async () => {
          seed();
          const link = await createLink(await sdkFor(ADMIN), false);
          const invitee = await signIn(INVITEE);

          // 1. Redeem the link
          await redeem(invitee.getPasswordManagerClient(), link);

          // 2. Verify the server holds an accepted membership with no organization key
          expect(inviteeMembership()).toMatchObject({
            status: "accepted",
            organizationKeySealedToMember: null,
          });

          // 3. Verify the invitee sent nothing that would need the organization key, which it
          //    cannot reach; an admin confirms it out of band instead
          const posted = postedTo("POST /organizations/users/invite-link/accept");
          expect(posted).not.toHaveProperty("orgUserKey");
          expect(posted).not.toHaveProperty("defaultUserCollectionName");

          // 4. Verify local state: until an admin confirms it, the invitee reaches only its own
          //    vault
          await expectLocalVault(invitee, INVITEE, accountSeed(INVITEE));

          // 5. Verify server state: a fresh login does the same
          await expectServerVault(INVITEE, accountSeed(INVITEE));
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "enrolls into account recovery while accepting without confirmation",
        async () => {
          seed();
          const link = await createLink(await sdkFor(ADMIN), false);
          const invitee = await sdkFor(INVITEE);

          // 1. Redeem the link, enrolling into account recovery
          await redeem(invitee, link, true);

          // 2. Verify the server holds an accepted membership with a recovery key
          const member = inviteeMembership();
          expect(member?.status).toBe("accepted");
          expect(member?.accountRecoveryKey).toMatch(/^\d+\./);
        },
        UNLOCK_TIMEOUT,
      );

      describe("failures", () => {
        it(
          "rejects with OrganizationHasNoAvailableSeats when the plan is full",
          async () => {
            seed({ seats: FULL });
            const link = await createLink(await sdkFor(ADMIN), true);
            const invitee = await signIn(INVITEE);

            // 1. Redeem the link
            const error = await rejection(
              redeem(invitee.getPasswordManagerClient(), link),
              isAcceptInviteLinkError,
            );

            // 2. Verify it was refused
            expect(error.variant).toBe("OrganizationHasNoAvailableSeats");

            // 3. Verify neither side moved
            expect(inviteeMembership()).toBeUndefined();
            await expectLocalVault(invitee, INVITEE, accountSeed(INVITEE));
          },
          UNLOCK_TIMEOUT,
        );

        // The server refuses these while the invitee fetches the invite, before it accepts or
        // confirms. That endpoint refuses with a plain message rather than a validation problem,
        // and the SDK only maps validation problems to typed variants, so these arrive as `Api`
        // carrying the server's message. The typed variants for these codes are only reachable if
        // the server or the SDK changes how the fetch is refused.
        describe("refused while fetching the invite", () => {
          it(
            "rejects a member who confirms",
            async () => {
              seed();
              const admin = await signIn(ADMIN);
              const link = await createLink(admin.getPasswordManagerClient(), true);
              const before = harness.server.getOrganization(organizationId).members;

              // 1. Redeem the link as a member already
              const error = await rejection(
                redeem(admin.getPasswordManagerClient(), link),
                isAcceptInviteLinkError,
              );

              // 2. Verify it was refused
              expect(error.variant).toBe("Api");
              expect(error.message).toContain(`You're already a member of ${org.seed.name}.`);

              // 3. Verify neither side moved
              expect(harness.server.getOrganization(organizationId).members).toEqual(before);
              await expectLocalVault(admin, ADMIN, withOrganizationVault(ADMIN));
            },
            UNLOCK_TIMEOUT,
          );

          it(
            "rejects a member who accepts",
            async () => {
              seed();
              const admin = await signIn(ADMIN);
              const link = await createLink(admin.getPasswordManagerClient(), false);
              const before = harness.server.getOrganization(organizationId).members;

              // 1. Redeem the link as a member already
              const error = await rejection(
                redeem(admin.getPasswordManagerClient(), link),
                isAcceptInviteLinkError,
              );

              // 2. Verify it was refused
              expect(error.variant).toBe("Api");
              expect(error.message).toContain(`You're already a member of ${org.seed.name}.`);

              // 3. Verify neither side moved
              expect(harness.server.getOrganization(organizationId).members).toEqual(before);
              await expectLocalVault(admin, ADMIN, withOrganizationVault(ADMIN));
            },
            UNLOCK_TIMEOUT,
          );

          it(
            "rejects once the plan drops invite links",
            async () => {
              seed();
              const link = await createLink(await sdkFor(ADMIN), true);
              harness.server.setOrganizationPlan(organizationId, { useInviteLinks: false });
              const invitee = await signIn(INVITEE);

              // 1. Redeem a link created before the plan dropped invite links
              const error = await rejection(
                redeem(invitee.getPasswordManagerClient(), link),
                isAcceptInviteLinkError,
              );

              // 2. Verify it was refused
              expect(error.variant).toBe("Api");
              expect(error.message).toContain(
                "Your organization's plan does not support invite links.",
              );

              // 3. Verify neither side moved
              expect(inviteeMembership()).toBeUndefined();
              await expectLocalVault(invitee, INVITEE, accountSeed(INVITEE));
            },
            UNLOCK_TIMEOUT,
          );

          it(
            "rejects an address on a domain the link does not allow",
            async () => {
              seed();
              const link = await createLink(await sdkFor(ADMIN), true, ["example.com"]);
              const invitee = await signIn(INVITEE);

              // 1. Redeem a link that does not allow the invitee's domain
              const error = await rejection(
                redeem(invitee.getPasswordManagerClient(), link),
                isAcceptInviteLinkError,
              );

              // 2. Verify it was refused
              expect(error.variant).toBe("Api");
              expect(error.message).toContain(
                `You're not allowed to join the ${org.seed.name} vault with your email domain.`,
              );

              // 3. Verify neither side moved
              expect(inviteeMembership()).toBeUndefined();
              await expectLocalVault(invitee, INVITEE, accountSeed(INVITEE));
            },
            UNLOCK_TIMEOUT,
          );
        });
      });
    });
  });

  /**
   * An admin creates a link and an invitee joins with it, holding nothing but the link. Everything
   * the invitee sends is derived from the secret in it, and the secret itself never leaves it.
   *
   *   admin    ──create──┐
   *                      │ sealed invite
   *   server   ──────────┴── code ──┬──────────────────┬── member, Confirmed, key sealed to invitee
   *                                 │ link             │
   *   invitee  ──unlock─────────────┴─▶ open(secret) ──┴─ confirm ─▶ sync ─▶ lock ─▶ unlock ─▶ reads
   *                                                    │
   *   relogin  ────────────────────────────────────────┴── login ─▶ unlock ─────────────────▶ reads
   */
  INVITEES.each(
    "$name round-trips an invite from an admin creating a link to joining with it",
    async (vector) => {
      seed({}, vector.name);

      // 1. The admin creates a link
      const link = await createLink(await sdkFor(ADMIN), true);

      // 2. The invitee, holding no organization key, redeems it and enrolls into account recovery
      const invitee = await signIn(vector.name);
      await redeem(invitee.getPasswordManagerClient(), link, true);

      // 3. Verify the server holds a confirmed membership with a recovery key
      const member = inviteeMembership(vector.name);
      expect(member?.status).toBe("confirmed");
      expect(member?.accountRecoveryKey).toEqual(expect.any(String));

      // 4. Verify the invite secret lives in the link, never on the wire
      expectNeverSent(parseFragment(link).secret);

      // 5. Verify local state: the invitee decrypts the organization's ciphers alongside its own
      await expectLocalVault(invitee, vector.name, withOrganizationVault(vector.name));

      // 6. Verify server state: a fresh login does the same
      await expectServerVault(vector.name, withOrganizationVault(vector.name));
    },
    UNLOCK_TIMEOUT,
  );

  /**
   * Checks `client` decrypts exactly the ciphers `expected` records, holding it to every field
   * since redeeming a link writes no cipher. Checks the ids as well, since `validateVault` only
   * compares the ciphers that did arrive.
   */
  async function expectVault(client: ClientEmulator, expected: SeedAccount): Promise<void> {
    await validateVault(client, expected, []);

    const { successes } = await client.getPasswordManagerClient().vault().ciphers().get_all();
    expect(successes.map((cipher) => String(cipher.id)).sort()).toEqual(
      (expected.vault?.ciphers ?? []).map((cipher) => cipher.id).sort(),
    );
  }

  /**
   * The client's own state: syncs down what the server now holds, then locks and unlocks, so the
   * organization keys the sync brought are the ones opened, and checks the vault.
   */
  async function expectLocalVault(
    client: ClientEmulator,
    vectorName: string,
    expected: SeedAccount,
  ): Promise<void> {
    await client.sync();
    await client.lock();
    await client.unlock(passwordOf(vectorName));
    await expectVault(client, expected);
  }

  /** The server's state: logs `vectorName` in afresh and checks the vault it syncs down. */
  async function expectServerVault(vectorName: string, expected: SeedAccount): Promise<void> {
    await expectVault(await signIn(vectorName), expected);
  }

  /** The plaintext `vectorName`'s own vault decrypts to. */
  function accountSeed(vectorName: string): SeedAccount {
    return toSeedAccount(testVectors.users.get(vectorName));
  }

  /** The plaintext `vectorName`'s vault decrypts to once it is a confirmed member. */
  function withOrganizationVault(vectorName: string): SeedAccount {
    const own = accountSeed(vectorName);
    return {
      ...own,
      vault: {
        ciphers: [...(own.vault?.ciphers ?? []), ...(org.seed.vault?.ciphers ?? [])],
        folders: own.vault?.folders,
      },
    };
  }
});
