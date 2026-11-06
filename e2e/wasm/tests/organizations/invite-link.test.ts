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
/** An account outside {@link ORGANIZATION}. Its low iteration count keeps unlocking it cheap. */
const INVITEE = "v1-pbkdf2-min-iterations";
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

  /** Seeds the organization, with {@link ADMIN} as its owner, and the invitee's account. */
  function seed(options: Omit<SeedOrganizationOptions, "roles"> = {}): void {
    org = harness.server.seedOrganizationTestVector(testVectors.organizations.get(ORGANIZATION), {
      ...options,
      roles: { [ADMIN]: "owner" },
    });
    organizationId = org.organizationId;
    harness.server.seedUserTestVector(testVectors.users.get(INVITEE));
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

  /** The invitee's membership as the server holds it, if any. */
  function inviteeMembership() {
    const invitee = harness.server.getUser(testVectors.users.get(INVITEE).account.email);
    return harness.server
      .getOrganization(organizationId)
      .members.find((member) => member.userId === invitee.userId);
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

          const link = await createLink(admin, true, ["Test.Bitwarden.com", "  other.com "]);

          const stored = harness.server.inviteLinkFor(organizationId);
          expect(stored).toBeDefined();
          expect(link.id).toBe(stored!.id);
          expect(link.organizationId).toBe(organizationId);
          expect(link.supportsConfirmation).toBe(true);
          // The server sanitizes the domains before storing them.
          expect(stored!.allowedDomains).toEqual(["test.bitwarden.com", "other.com"]);
          expect(link.allowedDomains).toEqual(stored!.allowedDomains);

          // The link carries the code the server generated, not one the client chose.
          const fragment = parseFragment(link);
          expect(fragment.organizationId).toBe(String(organizationId));
          expect(fragment.code).toBe(stored!.code);

          // The invite itself never crosses the boundary; the client only gets the link to share.
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

          const link = await createLink(admin);

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

          const error = await rejection(createLink(admin), isInviteLinkError);

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

          const error = await rejection(createLink(admin, true, ["   "]), isInviteLinkError);

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

          const error = await rejection(createLink(admin), isInviteLinkError);

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

          const error = await rejection(createLink(member), isInviteLinkError);

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

          expect(await admin.invite_link().admin().get(organizationId)).toBeUndefined();

          const created = await createLink(admin);
          const fetched = await admin.invite_link().admin().get(organizationId);

          expect(fetched?.id).toBe(created.id);
          // The secret is recovered from the stored invite, so the link reads the same every time.
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

          const refreshed = await admin.invite_link().admin().refresh(organizationId, true);

          const after = harness.server.inviteLinkFor(organizationId)!;
          expect(after.id).not.toBe(before.id);
          expect(after.code).not.toBe(before.code);
          expect(after.invite).not.toBe(before.invite);
          expect(after.allowedDomains).toEqual(before.allowedDomains);
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
          await admin.invite_link().admin().refresh(organizationId, true);
          const invitee = await sdkFor(INVITEE);

          const error = await rejection(redeem(invitee, handedOut), isAcceptInviteLinkError);

          expect(error.variant).toBe("LinkNotFound");
          expect(inviteeMembership()).toBeUndefined();
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

          const link = await admin.invite_link().admin().update_confirmation(organizationId, false);

          const after = harness.server.inviteLinkFor(organizationId)!;
          expect(after.supportsConfirmation).toBe(false);
          expect(link.supportsConfirmation).toBe(false);
          // The envelope is nulled out rather than dropped, and the other four are untouched.
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
          // Links already handed out keep working: same code, same secret.
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

          const link = await admin.invite_link().admin().update_confirmation(organizationId, true);

          const after = harness.server.inviteLinkFor(organizationId)!;
          expect(after.supportsConfirmation).toBe(true);
          expect(link.supportsConfirmation).toBe(true);
          // A fresh envelope appears where there was `null`; the invite key it wraps is unchanged,
          // so `organization_key_sealed_invite_key` must not be rotated.
          expect(envelopes(before.invite).invite_key_sealed_organization_key).toBeNull();
          expect(envelopes(after.invite).invite_key_sealed_organization_key).toEqual(
            expect.any(String),
          );
          expect(envelopes(after.invite).organization_key_sealed_invite_key).toBe(
            envelopes(before.invite).organization_key_sealed_invite_key,
          );
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

          await redeem(invitee, handedOut);

          // Confirmation was stripped, so the invitee could only accept.
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

          const link = await admin
            .invite_link()
            .admin()
            .update_allowed_domains(organizationId, [" Example.COM ", "other.org"]);

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

          await admin.invite_link().admin().delete(organizationId);

          expect(harness.server.inviteLinkFor(organizationId)).toBeUndefined();
          expect(await admin.invite_link().admin().get(organizationId)).toBeUndefined();

          const invitee = await sdkFor(INVITEE);
          const error = await rejection(redeem(invitee, handedOut), isAcceptInviteLinkError);
          expect(error.variant).toBe("LinkNotFound");
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

          const status = await invitee
            .invite_link()
            .user()
            .get_status(organizationId, parseFragment(link).code);

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

          const status = await invitee
            .invite_link()
            .user()
            .get_status(organizationId, parseFragment(link).code);

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

          const error = await rejection(
            invitee
              .invite_link()
              .user()
              .get_status(organizationId, "00000000-0000-4000-8000-000000000000"),
            isInviteLinkError,
          );

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
      it(
        "self-confirms when the invite supports confirmation, giving the invitee the organization",
        async () => {
          seed();
          const admin = await sdkFor(ADMIN);
          const link = await createLink(admin, true);
          const invitee = await sdkFor(INVITEE);

          await redeem(invitee, link);

          const member = inviteeMembership();
          expect(member?.status).toBe("confirmed");
          expect(member?.organizationKeySealedToMember).toMatch(/^\d+\./);
          // Not enrolling means no recovery key is stored at all.
          expect(member?.accountRecoveryKey).toBeUndefined();

          // The default collection name is organization data: it reaches the server encrypted with
          // the organization key, so an admin opens it, and its plaintext never crosses the wire.
          expect(member?.defaultCollectionName).toMatch(/^\d+\./);
          expect(defaultCollectionName(admin, member!.defaultCollectionName!)).toBe(
            COLLECTION_NAME,
          );
          expectNeverSent(COLLECTION_NAME);

          // The key the invitee sealed to itself is the real organization key: after a fresh login
          // it decrypts the organization's ciphers alongside its own.
          await expectInviteeVault(withOrganizationVault(INVITEE));
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "enrolls into account recovery when asked",
        async () => {
          seed();
          const link = await createLink(await sdkFor(ADMIN), true);
          const invitee = await sdkFor(INVITEE);

          await redeem(invitee, link, true);

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
          const invitee = await sdkFor(INVITEE);

          await redeem(invitee, link);

          expect(inviteeMembership()).toMatchObject({
            status: "accepted",
            organizationKeySealedToMember: null,
          });
          // Without confirmation the invitee cannot reach the organization key, so it sends nothing
          // that would need one; an admin confirms it out of band instead.
          const posted = postedTo("POST /organizations/users/invite-link/accept");
          expect(posted).not.toHaveProperty("orgUserKey");
          expect(posted).not.toHaveProperty("defaultUserCollectionName");
          // Until an admin confirms it, the invitee reaches only its own vault.
          await expectInviteeVault(accountSeed(INVITEE));
        },
        UNLOCK_TIMEOUT,
      );

      it(
        "enrolls into account recovery while accepting without confirmation",
        async () => {
          seed();
          const link = await createLink(await sdkFor(ADMIN), false);
          const invitee = await sdkFor(INVITEE);

          await redeem(invitee, link, true);

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
            const invitee = await sdkFor(INVITEE);

            const error = await rejection(redeem(invitee, link), isAcceptInviteLinkError);

            expect(error.variant).toBe("OrganizationHasNoAvailableSeats");
            expect(inviteeMembership()).toBeUndefined();
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
              const admin = await sdkFor(ADMIN);
              const link = await createLink(admin, true);
              const before = harness.server.getOrganization(organizationId).members;

              const error = await rejection(redeem(admin, link), isAcceptInviteLinkError);

              expect(error.variant).toBe("Api");
              expect(error.message).toContain(`You're already a member of ${org.seed.name}.`);
              expect(harness.server.getOrganization(organizationId).members).toEqual(before);
            },
            UNLOCK_TIMEOUT,
          );

          it(
            "rejects a member who accepts",
            async () => {
              seed();
              const admin = await sdkFor(ADMIN);
              const link = await createLink(admin, false);
              const before = harness.server.getOrganization(organizationId).members;

              const error = await rejection(redeem(admin, link), isAcceptInviteLinkError);

              expect(error.variant).toBe("Api");
              expect(error.message).toContain(`You're already a member of ${org.seed.name}.`);
              expect(harness.server.getOrganization(organizationId).members).toEqual(before);
            },
            UNLOCK_TIMEOUT,
          );

          it(
            "rejects once the plan drops invite links",
            async () => {
              seed();
              const link = await createLink(await sdkFor(ADMIN), true);
              const stored = harness.server.getOrganization(organizationId);
              harness.server.db.organizations.update(String(organizationId), {
                ...stored,
                useInviteLinks: false,
              });
              const invitee = await sdkFor(INVITEE);

              const error = await rejection(redeem(invitee, link), isAcceptInviteLinkError);

              expect(error.variant).toBe("Api");
              expect(error.message).toContain(
                "Your organization's plan does not support invite links.",
              );
              expect(inviteeMembership()).toBeUndefined();
            },
            UNLOCK_TIMEOUT,
          );

          it(
            "rejects an address on a domain the link does not allow",
            async () => {
              seed();
              const link = await createLink(await sdkFor(ADMIN), true, ["example.com"]);
              const invitee = await sdkFor(INVITEE);

              const error = await rejection(redeem(invitee, link), isAcceptInviteLinkError);

              expect(error.variant).toBe("Api");
              expect(error.message).toContain(
                `You're not allowed to join the ${org.seed.name} vault with your email domain.`,
              );
              expect(inviteeMembership()).toBeUndefined();
            },
            UNLOCK_TIMEOUT,
          );
        });
      });
    });
  });

  it(
    "round-trips an invite from an admin creating a link to an invitee joining with it",
    async () => {
      seed();
      const link = await createLink(await sdkFor(ADMIN), true);

      // The invitee holds no organization key; it has only the link, and everything it sends is
      // derived from the secret in it.
      const invitee = await sdkFor(INVITEE);
      await redeem(invitee, link, true);

      const member = inviteeMembership();
      expect(member?.status).toBe("confirmed");
      expect(member?.accountRecoveryKey).toEqual(expect.any(String));
      await expectInviteeVault(withOrganizationVault(INVITEE));

      // The whole point of the invite secret: it lives in the link, never on the wire.
      expectNeverSent(parseFragment(link).secret);
    },
    UNLOCK_TIMEOUT,
  );

  /**
   * Logs the invitee in afresh and checks it decrypts exactly the ciphers `expected` records.
   * Checks the ids as well, since `validateVault` only compares the ciphers that did arrive.
   */
  async function expectInviteeVault(expected: SeedAccount): Promise<void> {
    const client = await signIn(INVITEE);

    await validateVault(client, expected);

    const { successes } = await client.getPasswordManagerClient().vault().ciphers().get_all();
    expect(successes.map((cipher) => String(cipher.id)).sort()).toEqual(
      (expected.vault?.ciphers ?? []).map((cipher) => cipher.id).sort(),
    );
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
