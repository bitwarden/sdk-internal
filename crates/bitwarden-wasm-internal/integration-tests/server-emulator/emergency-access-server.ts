// An in-memory model of the api server's emergency access routes.
//
// A grant moves through the statuses in order, each step taken by one side:
//
//   grantor: invite ──► Invited ──► grantee: accept ──► Accepted ──► grantor: confirm ──► Confirmed
//                                                                                          │    ▲
//                                                        grantee: initiate ◄───────────────┘    │
//                                                                │                              │
//                                                        RecoveryInitiated ──► grantor: reject ─┤
//                                                                │                              │
//                                                        grantor: approve                       │
//                                                                │                              │
//                                                        RecoveryApproved ───► grantor: reject ─┘
//                                                                │
//                                             grantee: view (View) / takeover + password (Takeover)

import { randomUUID } from "node:crypto";

import type { Database } from "./database";
import {
  CipherResponse,
  EmergencyAccessGranteeDetailsResponse,
  EmergencyAccessGrantorDetailsResponse,
  EmergencyAccessStatus,
  EmergencyAccessTakeoverResponse,
  EmergencyAccessType,
  ListResponse,
  MasterPasswordUnlockDataModel,
  type EmergencyAccessAcceptRequest,
  type EmergencyAccessStatusValue,
  type EmergencyAccessTypeValue,
  type EmergencyAccessConfirmRequest,
  type EmergencyAccessInviteRequest,
  type EmergencyAccessPasswordRequest,
  type EmergencyAccessUpdateRequest,
  type EmergencyAccessViewResponse,
} from "./dto";
import type { EmergencyAccessEntity, UserEntity } from "./entities";
import type { MockReply, Routes } from "./http-mock";

import { authenticatedRoute } from "./authentication";
import { error, HTTP_BAD_REQUEST } from "./replies";

/** The server refuses every invalid emergency access request with the same message. */
const NOT_VALID = "Emergency Access not valid.";

/** A grant's id, so it cannot be swapped for another id. */
type GrantId = string & { readonly __brand: "GrantId" };

const asGrantId = (value: string): GrantId => value as GrantId;

/** Which side of a grant a request must come from. */
enum Side {
  Grantor,
  Grantee,
}

export class EmergencyAccessServer {
  constructor(private readonly db: Database) {}

  routes(): Routes {
    return {
      "GET /emergency-access/trusted": authenticatedRoute(this.db, (user) => this.trusted(user)),
      "GET /emergency-access/granted": authenticatedRoute(this.db, (user) => this.granted(user)),
      "POST /emergency-access/invite": authenticatedRoute(this.db, (user, request) =>
        this.invite(user, request.json<EmergencyAccessInviteRequest>()),
      ),

      "GET /emergency-access/:id": authenticatedRoute(this.db, (user, request) =>
        this.get(user, asGrantId(request.params.id)),
      ),
      "PUT /emergency-access/:id": authenticatedRoute(this.db, (user, request) =>
        this.update(
          user,
          asGrantId(request.params.id),
          request.json<EmergencyAccessUpdateRequest>(),
        ),
      ),
      "DELETE /emergency-access/:id": authenticatedRoute(this.db, (user, request) =>
        this.delete(user, asGrantId(request.params.id)),
      ),

      "POST /emergency-access/:id/reinvite": authenticatedRoute(this.db, (user, request) =>
        this.transition(user, asGrantId(request.params.id), Side.Grantor, [
          EmergencyAccessStatus.invited,
        ]),
      ),
      "POST /emergency-access/:id/accept": authenticatedRoute(this.db, (user, request) =>
        this.accept(
          user,
          asGrantId(request.params.id),
          request.json<EmergencyAccessAcceptRequest>(),
        ),
      ),
      "POST /emergency-access/:id/confirm": authenticatedRoute(this.db, (user, request) =>
        this.confirm(
          user,
          asGrantId(request.params.id),
          request.json<EmergencyAccessConfirmRequest>(),
        ),
      ),
      "POST /emergency-access/:id/initiate": authenticatedRoute(this.db, (user, request) =>
        this.transition(
          user,
          asGrantId(request.params.id),
          Side.Grantee,
          [EmergencyAccessStatus.confirmed],
          EmergencyAccessStatus.recoveryInitiated,
        ),
      ),
      "POST /emergency-access/:id/approve": authenticatedRoute(this.db, (user, request) =>
        this.transition(
          user,
          asGrantId(request.params.id),
          Side.Grantor,
          [EmergencyAccessStatus.recoveryInitiated],
          EmergencyAccessStatus.recoveryApproved,
        ),
      ),
      "POST /emergency-access/:id/reject": authenticatedRoute(this.db, (user, request) =>
        this.transition(
          user,
          asGrantId(request.params.id),
          Side.Grantor,
          [EmergencyAccessStatus.recoveryInitiated, EmergencyAccessStatus.recoveryApproved],
          EmergencyAccessStatus.confirmed,
        ),
      ),

      "POST /emergency-access/:id/view": authenticatedRoute(this.db, (user, request) =>
        this.view(user, asGrantId(request.params.id)),
      ),
      "POST /emergency-access/:id/takeover": authenticatedRoute(this.db, (user, request) =>
        this.takeover(user, asGrantId(request.params.id)),
      ),
      "POST /emergency-access/:id/password": authenticatedRoute(this.db, (user, request) =>
        this.password(
          user,
          asGrantId(request.params.id),
          request.json<EmergencyAccessPasswordRequest>(),
        ),
      ),
      "GET /emergency-access/:id/policies": authenticatedRoute(this.db, (user, request) =>
        this.policies(user, asGrantId(request.params.id)),
      ),
    };
  }

  /** The grant `id`, if `user` is on `side` of it. */
  private grantFor(user: UserEntity, id: GrantId, side: Side): EmergencyAccessEntity | undefined {
    const grant = this.db.emergencyAccess.get(id);
    if (grant === undefined) {
      return undefined;
    }

    const party = side === Side.Grantor ? grant.grantorId : grant.granteeId;
    return party === user.userId ? grant : undefined;
  }

  /** The grant `id`, if `user` is its grantee and it is approved for `type`. */
  private approvedFor(
    user: UserEntity,
    id: GrantId,
    type: EmergencyAccessTypeValue,
  ): EmergencyAccessEntity | undefined {
    const grant = this.grantFor(user, id, Side.Grantee);
    if (grant === undefined) {
      return undefined;
    }

    const approved = grant.status === EmergencyAccessStatus.recoveryApproved;
    return approved && grant.type === type ? grant : undefined;
  }

  private trusted(user: UserEntity): MockReply {
    const grants = this.db.emergencyAccess.filter((grant) => grant.grantorId === user.userId);
    const data = grants.map((grant) =>
      EmergencyAccessGranteeDetailsResponse.fromEntity(
        grant,
        grant.granteeId === null ? undefined : this.db.users.get(grant.granteeId),
      ),
    );

    return { json: ListResponse.of(data) };
  }

  private granted(user: UserEntity): MockReply {
    const grants = this.db.emergencyAccess.filter((grant) => grant.granteeId === user.userId);
    const data = grants.map((grant) =>
      EmergencyAccessGrantorDetailsResponse.fromEntity(grant, this.requireUser(grant.grantorId)),
    );

    return { json: ListResponse.of(data) };
  }

  private invite(user: UserEntity, posted: EmergencyAccessInviteRequest): MockReply {
    if (posted.email.toLowerCase() === user.email.toLowerCase()) {
      return error(HTTP_BAD_REQUEST, "You cannot add yourself as an emergency contact.");
    }

    const id = this.db.emergencyAccess.newId();
    this.db.emergencyAccess.set(id, {
      id,
      grantorId: user.userId,
      granteeId: null,
      email: posted.email,
      type: posted.type,
      status: EmergencyAccessStatus.invited,
      waitTimeDays: posted.waitTimeDays,
      keyEncrypted: null,
      inviteToken: randomUUID(),
    });
    this.db.revisions.next();

    return {};
  }

  private get(user: UserEntity, id: GrantId): MockReply {
    const grant = this.grantFor(user, id, Side.Grantor);
    if (grant === undefined) {
      return error(HTTP_BAD_REQUEST, NOT_VALID);
    }

    const grantee = grant.granteeId === null ? undefined : this.db.users.get(grant.granteeId);
    return { json: EmergencyAccessGranteeDetailsResponse.fromEntity(grant, grantee) };
  }

  private update(user: UserEntity, id: GrantId, posted: EmergencyAccessUpdateRequest): MockReply {
    const grant = this.grantFor(user, id, Side.Grantor);
    if (grant === undefined) {
      return error(HTTP_BAD_REQUEST, NOT_VALID);
    }

    this.db.emergencyAccess.update(id, {
      ...grant,
      type: posted.type,
      waitTimeDays: posted.waitTimeDays,
    });
    this.db.revisions.next();

    return {};
  }

  /** Either side may end a grant. */
  private delete(user: UserEntity, id: GrantId): MockReply {
    const grant = this.grantFor(user, id, Side.Grantor) ?? this.grantFor(user, id, Side.Grantee);
    if (grant === undefined) {
      return error(HTTP_BAD_REQUEST, NOT_VALID);
    }

    this.db.emergencyAccess.remove(id);
    return {};
  }

  /**
   * Moves a grant `user` is on `side` of from one of the `from` statuses to `to`.
   *
   * Without a `to`, the status is only checked — a reinvite resends the email and changes nothing.
   */
  private transition(
    user: UserEntity,
    id: GrantId,
    side: Side,
    from: EmergencyAccessStatusValue[],
    to?: EmergencyAccessStatusValue,
  ): MockReply {
    const grant = this.grantFor(user, id, side);
    if (grant === undefined || !from.includes(grant.status)) {
      return error(HTTP_BAD_REQUEST, NOT_VALID);
    }

    if (to !== undefined) {
      this.db.emergencyAccess.update(id, { ...grant, status: to });
      this.db.revisions.next();
    }

    return {};
  }

  /** The invited account claims the grant, proving it received the invite email. */
  private accept(user: UserEntity, id: GrantId, posted: EmergencyAccessAcceptRequest): MockReply {
    const grant = this.db.emergencyAccess.get(id);
    if (grant === undefined) {
      return error(HTTP_BAD_REQUEST, NOT_VALID);
    }
    if (grant.inviteToken !== posted.token) {
      return error(HTTP_BAD_REQUEST, "Invalid token.");
    }
    if (grant.status !== EmergencyAccessStatus.invited) {
      return error(HTTP_BAD_REQUEST, "Invitation already accepted.");
    }
    if (grant.email.toLowerCase() !== user.email.toLowerCase()) {
      return error(HTTP_BAD_REQUEST, "User email does not match invite.");
    }

    this.db.emergencyAccess.update(id, {
      ...grant,
      granteeId: user.userId,
      status: EmergencyAccessStatus.accepted,
    });
    this.db.revisions.next();

    return {};
  }

  /** The grantor seals their user key to the grantee, which is what later grants access at all. */
  private confirm(user: UserEntity, id: GrantId, posted: EmergencyAccessConfirmRequest): MockReply {
    const grant = this.grantFor(user, id, Side.Grantor);
    if (grant === undefined || grant.status !== EmergencyAccessStatus.accepted) {
      return error(HTTP_BAD_REQUEST, NOT_VALID);
    }

    this.db.emergencyAccess.update(id, {
      ...grant,
      keyEncrypted: posted.key,
      status: EmergencyAccessStatus.confirmed,
    });
    this.db.revisions.next();

    return {};
  }

  /** The grantor's own items only: organization items stay under keys the grantee never gets. */
  private view(user: UserEntity, id: GrantId): MockReply {
    const grant = this.approvedFor(user, id, EmergencyAccessType.view);
    if (grant?.keyEncrypted == null) {
      return error(HTTP_BAD_REQUEST, NOT_VALID);
    }

    const ciphers = this.db.ciphers
      .filter((entity) => entity.userId === grant.grantorId)
      .map((entity) => CipherResponse.fromCipher(entity.cipher));
    const body: EmergencyAccessViewResponse = {
      object: "emergencyAccessView",
      keyEncrypted: grant.keyEncrypted,
      ciphers,
    };

    return { json: body };
  }

  /** What the grantee needs to set the grantor a new master password: the key and its KDF. */
  private takeover(user: UserEntity, id: GrantId): MockReply {
    const grant = this.approvedFor(user, id, EmergencyAccessType.takeover);
    if (grant?.keyEncrypted == null) {
      return error(HTTP_BAD_REQUEST, NOT_VALID);
    }

    const grantor = this.requireUser(grant.grantorId);
    if (grantor.masterPasswordUnlock === null) {
      return error(HTTP_BAD_REQUEST, "You cannot take over an account without a master password.");
    }

    return {
      json: EmergencyAccessTakeoverResponse.from(grant.keyEncrypted, grantor.masterPasswordUnlock),
    };
  }

  private password(
    user: UserEntity,
    id: GrantId,
    posted: EmergencyAccessPasswordRequest,
  ): MockReply {
    const grant = this.approvedFor(user, id, EmergencyAccessType.takeover);
    if (grant === undefined) {
      return error(HTTP_BAD_REQUEST, NOT_VALID);
    }

    const { unlockData, authenticationData } = posted;
    if (unlockData == null || authenticationData == null) {
      return error(HTTP_BAD_REQUEST, "unlock and authentication data required");
    }
    if (unlockData.salt !== authenticationData.salt) {
      return error(HTTP_BAD_REQUEST, "unlock and authentication data disagree on the salt");
    }

    const grantor = this.requireUser(grant.grantorId);
    grantor.masterPasswordUnlock = MasterPasswordUnlockDataModel.toStored(unlockData);
    grantor.kdf = grantor.masterPasswordUnlock.kdf;
    this.db.revisions.next();

    return {};
  }

  private policies(user: UserEntity, id: GrantId): MockReply {
    if (this.approvedFor(user, id, EmergencyAccessType.takeover) === undefined) {
      return error(HTTP_BAD_REQUEST, NOT_VALID);
    }

    return { json: ListResponse.of([]) };
  }

  private requireUser(userId: string): UserEntity {
    const user = this.db.users.get(userId);
    if (user === undefined) {
      throw new Error(`emergency access references unknown account ${userId}`);
    }

    return user;
  }
}
