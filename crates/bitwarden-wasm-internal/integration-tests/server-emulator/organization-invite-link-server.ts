// An in-memory model of the api server's organization invite link routes, and the organization key
// routes an admin and an invitee need alongside them.
//
// An organization has at most one link. An admin creates it holding an invite sealed client-side;
// the server stores the invite without being able to open it, and generates the code the link
// carries. An invitee then presents the code to fetch the invite, opens it with the secret only the
// link carries, and joins:
//
//   admin: create ──► link ──► admin: support-confirm (same code) / refresh (new code) / delete
//                       │
//   invitee: invite ────┴──► accept  ──► member, Accepted (an admin still has to confirm)
//                       └──► confirm ──► member, Confirmed (holds the organization key at once)
//
// Refusals follow the real server's `InviteLinkRules`, in its order. Policies (auto-confirm, single
// organization, two-step login) are not modelled: the emulator has none.

import type { Database } from "./database";
import {
  InviteLinkEmailDomainResponse,
  InviteLinkStatusResponse,
  OrganizationInviteLinkResponse,
  OrganizationPrivateKeyResponse,
  OrganizationPublicKeyResponse,
  type AcceptInviteLinkRequest,
  type ConfirmInviteLinkRequest,
  type CreateOrganizationInviteLinkRequest,
  type InviteLinkCodeRequest,
  type InviteLinkEmailDomainRequest,
  type OrganizationInviteRequest,
  type OrganizationInviteResponse,
  type UpdateOrganizationInviteLinkRequest,
} from "./dto";
import type {
  OrganizationEntity,
  OrganizationInviteLinkEntity,
  OrganizationMember,
  UserEntity,
} from "./entities";
import type { MockReply, MockRequest, Routes } from "./http-mock";

import { authenticatedRoute } from "./authentication";
import {
  error,
  HTTP_BAD_REQUEST,
  HTTP_CONFLICT,
  HTTP_CREATED,
  HTTP_NO_CONTENT,
  HTTP_NOT_FOUND,
  validationProblem,
} from "./replies";

// The real server's messages (`InviteLinks/Errors.cs`), so a test reads what a client would.
const LINK_NOT_FOUND = "Invite link not found.";
const LINK_ALREADY_EXISTS = "An invite link already exists for this organization.";
const DOMAINS_REQUIRED = "At least one allowed domain is required.";
const NOT_AVAILABLE = "Your organization's plan does not support invite links.";
const CONFIRMATION_NOT_SUPPORTED = "This invite link does not support confirmation.";
const EMAIL_NOT_VERIFIED = "You must verify your email address before joining an organization.";
const NOT_PERMITTED = "Resource not found.";

const domainNotAllowed = (org: OrganizationEntity) =>
  `You're not allowed to join the ${org.name} vault with your email domain.`;
const alreadyMember = (org: OrganizationEntity) => `You're already a member of ${org.name}.`;
const noSeats = (org: OrganizationEntity) => `The ${org.name} vault has no available seats.`;

/**
 * Why an invitee may not join, carrying both forms the server answers in: `accept` and `invite`
 * refuse with a plain message, `confirm` with a validation problem naming a code and property.
 */
interface Refusal {
  status: number;
  message: string;
  code: string;
  property: string;
}

/** A link that could not be found answers 404 everywhere, in the plain form even from `confirm`. */
const linkNotFound: Refusal = {
  status: HTTP_NOT_FOUND,
  message: LINK_NOT_FOUND,
  code: "invite_link_not_found",
  property: "code",
};

const plain = (refusal: Refusal): MockReply => error(refusal.status, refusal.message);

const problem = (refusal: Refusal): MockReply =>
  refusal.status === HTTP_NOT_FOUND
    ? plain(refusal)
    : validationProblem(refusal.property, refusal.code, refusal.message);

/** Which membership an invitee may already hold and still redeem a link. */
enum Joining {
  /** Accepting needs no membership at all. */
  Accept,
  /** Confirming upgrades an accepted membership, so only a confirmed one blocks it. */
  Confirm,
}

/** An organization and its link, once the invitee has proved it holds the link's code. */
interface Eligible {
  org: OrganizationEntity;
  link: OrganizationInviteLinkEntity;
}

/** Trims, lowercases and drops blanks, as the server's `InviteLinkDomainSanitizer` does. */
function sanitizeDomains(domains: string[]): string[] {
  return domains.map((domain) => domain.trim().toLowerCase()).filter((domain) => domain !== "");
}

/** Whether `email`'s domain is one of `allowed`, compared exactly. */
function domainAllowed(email: string, allowed: string[]): boolean {
  const at = email.lastIndexOf("@");
  if (at < 1) {
    return false;
  }

  return allowed.includes(email.slice(at + 1).toLowerCase());
}

export class OrganizationInviteLinkServer {
  constructor(private readonly db: Database) {}

  routes(): Routes {
    return {
      // Unauthenticated: a prospective invitee checks a link before it has an account.
      "POST /organizations/invite-link/status": (request) =>
        this.status(request.json<InviteLinkCodeRequest>()),
      "POST /organizations/invite-link/validate-email-domain": (request) =>
        this.validateEmailDomain(request.json<InviteLinkEmailDomainRequest>()),

      // The invitee, signed in.
      "POST /organizations/users/invite-link/invite": authenticatedRoute(this.db, (user, request) =>
        this.invite(user, request.json<InviteLinkCodeRequest>()),
      ),
      "POST /organizations/users/invite-link/accept": authenticatedRoute(this.db, (user, request) =>
        this.accept(user, request.json<AcceptInviteLinkRequest>()),
      ),
      "POST /organizations/users/invite-link/confirm": authenticatedRoute(
        this.db,
        (user, request) => this.confirm(user, request.json<ConfirmInviteLinkRequest>()),
      ),

      // Organization keys.
      "GET /organizations/:orgId/private-key": authenticatedRoute(this.db, (user, request) =>
        this.privateKey(user, request),
      ),
      "GET /organizations/:orgId/public-key": authenticatedRoute(this.db, (_user, request) =>
        this.publicKey(request),
      ),

      // Administration.
      "GET /organizations/:orgId/invite-link": this.adminRoute((org) => this.get(org)),
      "POST /organizations/:orgId/invite-link": this.adminRoute((org, request) =>
        this.create(org, request.json<CreateOrganizationInviteLinkRequest>()),
      ),
      "PUT /organizations/:orgId/invite-link": this.adminRoute((org, request) =>
        this.updateDomains(org, request.json<UpdateOrganizationInviteLinkRequest>()),
      ),
      "DELETE /organizations/:orgId/invite-link": this.adminRoute((org) => this.delete(org)),
      "PUT /organizations/:orgId/invite-link/support-confirm": this.adminRoute((org, request) =>
        this.supportConfirm(org, request.json<OrganizationInviteRequest>()),
      ),
      "POST /organizations/:orgId/invite-link/refresh": this.adminRoute((org, request) =>
        this.refresh(org, request.json<OrganizationInviteRequest>()),
      ),
    };
  }

  /** A route only a confirmed owner or admin of the organization in the path may use. */
  private adminRoute(
    handler: (org: OrganizationEntity, request: MockRequest) => MockReply,
  ): ReturnType<typeof authenticatedRoute> {
    return authenticatedRoute(this.db, (user, request) => {
      const org = this.db.organizations.get(request.params.orgId);
      const member = org === undefined ? undefined : this.memberOf(org, user);
      if (
        org === undefined ||
        member?.status !== "confirmed" ||
        (member.role !== "owner" && member.role !== "admin")
      ) {
        return error(HTTP_NOT_FOUND, NOT_PERMITTED);
      }

      return handler(org, request);
    });
  }

  private memberOf(org: OrganizationEntity, user: UserEntity): OrganizationMember | undefined {
    return org.members.find((member) => member.userId === user.userId);
  }

  /** Whether the plan has room for one more member. */
  private seatsAvailable(org: OrganizationEntity): boolean {
    return org.seats === null || org.members.length < org.seats;
  }

  // ── Organization keys ──────────────────────────────────────────────────────────────────────────

  /** The private key, wrapped by the organization key, so only members can open it anyway. */
  private privateKey(user: UserEntity, request: MockRequest): MockReply {
    const org = this.db.organizations.get(request.params.orgId);
    if (org === undefined || this.memberOf(org, user)?.status !== "confirmed") {
      return error(HTTP_NOT_FOUND, NOT_PERMITTED);
    }

    const body: OrganizationPrivateKeyResponse = {
      object: "organizationPrivateKey",
      privateKey: org.wrappedPrivateKey ?? null,
    };
    return { json: body };
  }

  /** Public by nature: an invitee enrolling into account recovery needs it before joining. */
  private publicKey(request: MockRequest): MockReply {
    const org = this.db.organizations.get(request.params.orgId);
    if (org === undefined) {
      return error(HTTP_NOT_FOUND, NOT_PERMITTED);
    }

    const body: OrganizationPublicKeyResponse = {
      object: "organizationPublicKey",
      publicKey: org.publicKey ?? null,
    };
    return { json: body };
  }

  // ── Administration ─────────────────────────────────────────────────────────────────────────────

  private notAvailable(org: OrganizationEntity): MockReply | undefined {
    return org.useInviteLinks ? undefined : error(HTTP_BAD_REQUEST, NOT_AVAILABLE);
  }

  private get(org: OrganizationEntity): MockReply {
    const refused = this.notAvailable(org);
    if (refused !== undefined) {
      return refused;
    }

    const link = this.db.inviteLinks.get(org.organizationId);
    if (link === undefined) {
      return error(HTTP_NOT_FOUND, LINK_NOT_FOUND);
    }

    return { json: OrganizationInviteLinkResponse.fromEntity(link) };
  }

  private create(org: OrganizationEntity, posted: CreateOrganizationInviteLinkRequest): MockReply {
    const refused = this.notAvailable(org);
    if (refused !== undefined) {
      return refused;
    }

    const allowedDomains = sanitizeDomains(posted.allowedDomains);
    if (allowedDomains.length === 0) {
      return error(HTTP_BAD_REQUEST, DOMAINS_REQUIRED);
    }
    if (this.db.inviteLinks.get(org.organizationId) !== undefined) {
      return error(HTTP_CONFLICT, LINK_ALREADY_EXISTS);
    }

    const link = this.newLink(org, allowedDomains, posted);
    return { status: HTTP_CREATED, json: OrganizationInviteLinkResponse.fromEntity(link) };
  }

  private updateDomains(
    org: OrganizationEntity,
    posted: UpdateOrganizationInviteLinkRequest,
  ): MockReply {
    const refused = this.notAvailable(org);
    if (refused !== undefined) {
      return refused;
    }

    const allowedDomains = sanitizeDomains(posted.allowedDomains);
    if (allowedDomains.length === 0) {
      return error(HTTP_BAD_REQUEST, DOMAINS_REQUIRED);
    }

    const link = this.db.inviteLinks.get(org.organizationId);
    if (link === undefined) {
      return error(HTTP_NOT_FOUND, LINK_NOT_FOUND);
    }

    const updated = { ...link, allowedDomains, revisionDate: this.db.revisions.next() };
    this.db.inviteLinks.update(org.organizationId, updated);

    return { json: OrganizationInviteLinkResponse.fromEntity(updated) };
  }

  /** Re-seals the invite in place. The code is untouched, so links already handed out still work. */
  private supportConfirm(org: OrganizationEntity, posted: OrganizationInviteRequest): MockReply {
    const refused = this.notAvailable(org);
    if (refused !== undefined) {
      return refused;
    }

    const link = this.db.inviteLinks.get(org.organizationId);
    if (link === undefined) {
      return error(HTTP_NOT_FOUND, LINK_NOT_FOUND);
    }

    const updated = {
      ...link,
      invite: posted.invite,
      supportsConfirmation: posted.supportsConfirmation,
      revisionDate: this.db.revisions.next(),
    };
    this.db.inviteLinks.update(org.organizationId, updated);

    return { json: OrganizationInviteLinkResponse.fromEntity(updated) };
  }

  /** Replaces the link with a new id and code, keeping its domains: old links stop working. */
  private refresh(org: OrganizationEntity, posted: OrganizationInviteRequest): MockReply {
    const refused = this.notAvailable(org);
    if (refused !== undefined) {
      return refused;
    }

    const link = this.db.inviteLinks.get(org.organizationId);
    if (link === undefined) {
      return error(HTTP_NOT_FOUND, LINK_NOT_FOUND);
    }

    const replaced = this.newLink(org, link.allowedDomains, posted);
    return { json: OrganizationInviteLinkResponse.fromEntity(replaced) };
  }

  /** The one admin route with no plan check, so a downgraded organization can still clean up. */
  private delete(org: OrganizationEntity): MockReply {
    if (this.db.inviteLinks.get(org.organizationId) === undefined) {
      return error(HTTP_NOT_FOUND, LINK_NOT_FOUND);
    }

    this.db.inviteLinks.remove(org.organizationId);
    this.db.revisions.next();

    return { status: HTTP_NO_CONTENT };
  }

  private newLink(
    org: OrganizationEntity,
    allowedDomains: string[],
    posted: OrganizationInviteRequest,
  ): OrganizationInviteLinkEntity {
    const now = this.db.revisions.next();
    const link: OrganizationInviteLinkEntity = {
      id: this.db.inviteLinks.newId(),
      code: this.db.inviteLinkCodes.next(),
      organizationId: org.organizationId,
      allowedDomains,
      invite: posted.invite,
      supportsConfirmation: posted.supportsConfirmation,
      creationDate: now,
      revisionDate: now,
    };
    this.db.inviteLinks.set(org.organizationId, link);

    return link;
  }

  // ── Before signing in ──────────────────────────────────────────────────────────────────────────

  /** The organization and its link, if `posted` names an enabled organization's current code. */
  private linkFor(posted: InviteLinkCodeRequest): Eligible | undefined {
    const org = this.db.organizations.get(posted.organizationId);
    const link = this.db.inviteLinks.get(posted.organizationId);
    if (org === undefined || !org.enabled || link === undefined || link.code !== posted.code) {
      return undefined;
    }

    return { org, link };
  }

  private status(posted: InviteLinkCodeRequest): MockReply {
    const found = this.linkFor(posted);
    if (found === undefined) {
      return error(HTTP_NOT_FOUND, LINK_NOT_FOUND);
    }

    const { org, link } = found;
    const body: InviteLinkStatusResponse = org.useInviteLinks
      ? {
          object: "inviteLinkStatus",
          organizationName: org.name,
          linksEnabled: true,
          seatsAvailable: this.seatsAvailable(org),
          supportsConfirmation: link.supportsConfirmation,
          sso: null,
        }
      : {
          object: "inviteLinkStatus",
          organizationName: org.name,
          linksEnabled: false,
          seatsAvailable: false,
          supportsConfirmation: false,
          sso: null,
        };

    return { json: body };
  }

  /** A disallowed domain is an answer, not a refusal. */
  private validateEmailDomain(posted: InviteLinkEmailDomainRequest): MockReply {
    const found = this.linkFor(posted);
    if (found === undefined) {
      return error(HTTP_NOT_FOUND, LINK_NOT_FOUND);
    }
    const refused = this.notAvailable(found.org);
    if (refused !== undefined) {
      return refused;
    }

    const body: InviteLinkEmailDomainResponse = {
      isAllowed: domainAllowed(posted.email, found.link.allowedDomains),
    };
    return { json: body };
  }

  // ── The invitee ────────────────────────────────────────────────────────────────────────────────

  /**
   * The server's `InviteLinkRules`: the link must exist under that code, the plan must include
   * invite links, and `user` must be allowed to join `joining` the way it asks. The domain check
   * runs before the verified-email check on purpose, so an unverified address on a foreign domain
   * learns nothing about verification.
   */
  private eligibility(
    user: UserEntity,
    posted: InviteLinkCodeRequest,
    joining: Joining,
  ): Eligible | Refusal {
    const found = this.linkFor(posted);
    if (found === undefined) {
      return linkNotFound;
    }

    const { org, link } = found;
    if (!org.useInviteLinks) {
      return {
        status: HTTP_BAD_REQUEST,
        message: NOT_AVAILABLE,
        code: "invite_link_not_available",
        property: "code",
      };
    }
    if (!domainAllowed(user.email, link.allowedDomains)) {
      return {
        status: HTTP_BAD_REQUEST,
        message: domainNotAllowed(org),
        code: "email_domain_not_allowed",
        property: "code",
      };
    }
    if (user.emailVerified === false) {
      return {
        status: HTTP_BAD_REQUEST,
        message: EMAIL_NOT_VERIFIED,
        code: "email_not_verified",
        property: "organizationId",
      };
    }

    const member = this.memberOf(org, user);
    const blocking = joining === Joining.Confirm ? ["confirmed"] : ["accepted", "confirmed"];
    if (member !== undefined && blocking.includes(member.status)) {
      return {
        status: HTTP_BAD_REQUEST,
        message: alreadyMember(org),
        code: "already_organization_member",
        property: "code",
      };
    }

    return found;
  }

  /** A seat for `user`, unless it already holds one. */
  private seatRefusal(org: OrganizationEntity, user: UserEntity): Refusal | undefined {
    if (this.memberOf(org, user) !== undefined || this.seatsAvailable(org)) {
      return undefined;
    }

    return {
      status: HTTP_BAD_REQUEST,
      message: noSeats(org),
      code: "organization_has_no_available_seats",
      property: "code",
    };
  }

  /** The sealed invite, for the invitee to open with the secret from the link. */
  private invite(user: UserEntity, posted: InviteLinkCodeRequest): MockReply {
    const found = this.linkFor(posted);
    const joining = found?.link.supportsConfirmation === true ? Joining.Confirm : Joining.Accept;

    const eligible = this.eligibility(user, posted, joining);
    if ("status" in eligible) {
      return plain(eligible);
    }

    const body: OrganizationInviteResponse = { invite: eligible.link.invite };
    return { json: body };
  }

  /** Joins as an accepted member. An admin still has to confirm it before it holds any key. */
  private accept(user: UserEntity, posted: AcceptInviteLinkRequest): MockReply {
    const eligible = this.eligibility(user, posted, Joining.Accept);
    if ("status" in eligible) {
      return plain(eligible);
    }
    const noSeat = this.seatRefusal(eligible.org, user);
    if (noSeat !== undefined) {
      return plain(noSeat);
    }

    this.join(eligible.org, user, {
      status: "accepted",
      organizationKeySealedToMember: null,
      accountRecoveryKey: posted.resetPasswordKey ?? undefined,
    });

    return {};
  }

  /**
   * Joins as a confirmed member holding the organization key the invitee sealed to itself, which it
   * could only recover by opening the invite with the link's secret.
   */
  private confirm(user: UserEntity, posted: ConfirmInviteLinkRequest): MockReply {
    const eligible = this.eligibility(user, posted, Joining.Confirm);
    if ("status" in eligible) {
      return problem(eligible);
    }
    if (!eligible.link.supportsConfirmation) {
      return validationProblem(
        "code",
        "invite_link_confirmation_not_supported",
        CONFIRMATION_NOT_SUPPORTED,
      );
    }
    const noSeat = this.seatRefusal(eligible.org, user);
    if (noSeat !== undefined) {
      return problem(noSeat);
    }

    this.join(eligible.org, user, {
      status: "confirmed",
      organizationKeySealedToMember: posted.orgUserKey,
      accountRecoveryKey: posted.resetPasswordKey ?? undefined,
      // The server names the member's default collection with this, so it is stored as posted.
      defaultCollectionName: posted.defaultUserCollectionName,
    });
    // A sync hands an account the organization keys sealed to it, so the next unlock opens them.
    this.db.users.update(user.userId, {
      ...user,
      organizationKeys: {
        ...user.organizationKeys,
        [eligible.org.organizationId]: posted.orgUserKey,
      },
    });

    return {};
  }

  /** Adds `user` to `org`, or moves its existing membership on, as a plain member. */
  private join(
    org: OrganizationEntity,
    user: UserEntity,
    membership: Pick<
      OrganizationMember,
      "status" | "organizationKeySealedToMember" | "accountRecoveryKey" | "defaultCollectionName"
    >,
  ): void {
    const existing = this.memberOf(org, user);
    const member: OrganizationMember = {
      userId: user.userId,
      role: existing?.role ?? "user",
      ...membership,
      accountRecoveryKey: membership.accountRecoveryKey ?? existing?.accountRecoveryKey,
    };

    this.db.organizations.update(org.organizationId, {
      ...org,
      members: [...org.members.filter((other) => other.userId !== user.userId), member],
    });
    this.db.revisions.next();
  }
}
