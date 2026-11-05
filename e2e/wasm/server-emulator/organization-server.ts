// An in-memory model of the api server's organization administration routes.
//
// Every route here needs the Manage Users permission, which owners and admins hold. A caller
// without it is answered 404, as the real server does, so the organization's existence is not
// revealed.
//
// A member who has not joined moves through:
//
//   admin: stage ──► Staged ──► admin: send invite ──► Invited ──► admin: reinvite ──► Invited

import type { Database } from "./database";
import {
  ListResponse,
  OrganizationDomainMiniResponse,
  OrganizationUserBulkResponse,
  type OrganizationUserBulkRequest,
} from "./dto";
import {
  OrganizationRole,
  PendingMemberStatus,
  type OrganizationEntity,
  type UserEntity,
} from "./entities";
import type { MockReply, Routes } from "./http-mock";

import { authenticatedRoute } from "./authentication";
import { error, HTTP_BAD_REQUEST, HTTP_NOT_FOUND } from "./replies";

const NOT_STAGED = "User is not staged.";
const NOT_INVITED = "User invalid.";

const MANAGES_USERS: readonly OrganizationRole[] = [OrganizationRole.Owner, OrganizationRole.Admin];

export class OrganizationServer {
  constructor(private readonly db: Database) {}

  routes(): Routes {
    return {
      "GET /organizations/:orgId/domain/mini": authenticatedRoute(this.db, (user, request) =>
        this.asUserManager(user, request.params.orgId, (organization) => ({
          json: ListResponse.of(
            organization.domains.map(OrganizationDomainMiniResponse.fromDomain),
          ),
        })),
      ),

      "POST /organizations/:orgId/users/send-invite": authenticatedRoute(this.db, (user, request) =>
        this.asUserManager(user, request.params.orgId, (organization) =>
          this.sendInvites(organization, request.json<OrganizationUserBulkRequest>().ids),
        ),
      ),

      "POST /organizations/:orgId/users/reinvite": authenticatedRoute(this.db, (user, request) =>
        this.asUserManager(user, request.params.orgId, (organization) =>
          this.reinvite(organization, request.json<OrganizationUserBulkRequest>().ids),
        ),
      ),

      "POST /organizations/:orgId/users/:id/reinvite": authenticatedRoute(
        this.db,
        (user, request) =>
          this.asUserManager(user, request.params.orgId, (organization) => {
            const [outcome] = this.reinvite(organization, [request.params.id]).json.data;
            return outcome.error === "" ? {} : error(HTTP_BAD_REQUEST, outcome.error);
          }),
      ),
    };
  }

  /** Runs `handler` on the organization if `user` may manage its users, 404s otherwise. */
  private asUserManager(
    user: UserEntity,
    organizationId: string,
    handler: (organization: OrganizationEntity) => MockReply,
  ): MockReply {
    const organization = this.db.organizations.get(organizationId);
    const member = organization?.members.find((candidate) => candidate.userId === user.userId);
    if (
      organization === undefined ||
      member === undefined ||
      !MANAGES_USERS.includes(member.role)
    ) {
      return error(HTTP_NOT_FOUND, `no organization ${organizationId} this account manages`);
    }

    return handler(organization);
  }

  /** Promotes staged members to invited. Any other id is reported, not refused. */
  private sendInvites(
    organization: OrganizationEntity,
    ids: string[],
  ): { json: ListResponse<OrganizationUserBulkResponse> } {
    const outcomes = ids.map((id) => {
      const member = organization.pendingMembers.find((candidate) => candidate.id === id);
      if (member?.status !== PendingMemberStatus.Staged) {
        return OrganizationUserBulkResponse.of(id, NOT_STAGED);
      }

      member.status = PendingMemberStatus.Invited;
      return OrganizationUserBulkResponse.of(id, "");
    });

    return { json: ListResponse.of(outcomes) };
  }

  /** Re-sends invites to invited members. Any other id is reported, not refused. */
  private reinvite(
    organization: OrganizationEntity,
    ids: string[],
  ): { json: ListResponse<OrganizationUserBulkResponse> } {
    const outcomes = ids.map((id) => {
      const member = organization.pendingMembers.find((candidate) => candidate.id === id);
      const invited = member?.status === PendingMemberStatus.Invited;

      return OrganizationUserBulkResponse.of(id, invited ? "" : NOT_INVITED);
    });

    return { json: ListResponse.of(outcomes) };
  }
}
