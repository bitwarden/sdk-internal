// Organization invite links, as the server takes and serves them.

import type { OrganizationInviteLinkEntity } from "../entities";

/** `OrganizationInviteLinkResponseModel`. The revision date is stored but never served. */
export class OrganizationInviteLinkResponse {
  object!: "organizationInviteLink";
  id!: string;
  code!: string;
  organizationId!: string;
  allowedDomains!: string[];
  invite!: string;
  supportsConfirmation!: boolean;
  creationDate!: string;

  static fromEntity(entity: OrganizationInviteLinkEntity): OrganizationInviteLinkResponse {
    return {
      object: "organizationInviteLink",
      id: entity.id,
      code: entity.code,
      organizationId: entity.organizationId,
      allowedDomains: entity.allowedDomains,
      invite: entity.invite,
      supportsConfirmation: entity.supportsConfirmation,
      creationDate: entity.creationDate,
    };
  }
}

/** `CreateOrganizationInviteLinkRequestModel`. */
export class CreateOrganizationInviteLinkRequest {
  allowedDomains!: string[];
  invite!: string;
  supportsConfirmation!: boolean;
}

/** `UpdateOrganizationInviteLinkRequestModel`: replaces the allowed domains. */
export class UpdateOrganizationInviteLinkRequest {
  allowedDomains!: string[];
}

/** The body of both `refresh` and `support-confirm`: a re-sealed invite and its flag. */
export class OrganizationInviteRequest {
  invite!: string;
  supportsConfirmation!: boolean;
}

/** What every unauthenticated and invitee invite link request names: the organization and code. */
export class InviteLinkCodeRequest {
  organizationId!: string;
  code!: string;
}

/** `ValidateOrganizationInviteLinkEmailDomainRequestModel`. */
export class InviteLinkEmailDomainRequest extends InviteLinkCodeRequest {
  email!: string;
}

/** `ValidateEmailDomainResponseModel`. */
export class InviteLinkEmailDomainResponse {
  isAllowed!: boolean;
}

/** `OrganizationInviteLinkStatusResponseModel`. The emulator models no SSO, so `sso` is `null`. */
export class InviteLinkStatusResponse {
  object!: "inviteLinkStatus";
  organizationName!: string | null;
  linksEnabled!: boolean;
  seatsAvailable!: boolean;
  supportsConfirmation!: boolean;
  sso!: null;
}

/** What `POST /organizations/users/invite-link/invite` answers with: the sealed invite. */
export class OrganizationInviteResponse {
  invite!: string;
}

/** `AcceptOrganizationInviteLinkRequestModel`. */
export class AcceptInviteLinkRequest extends InviteLinkCodeRequest {
  resetPasswordKey?: string | null;
}

/** `ConfirmOrganizationInviteLinkRequestModel`: accepting and confirming in one step. */
export class ConfirmInviteLinkRequest extends AcceptInviteLinkRequest {
  orgUserKey!: string;
  defaultUserCollectionName!: string;
}
