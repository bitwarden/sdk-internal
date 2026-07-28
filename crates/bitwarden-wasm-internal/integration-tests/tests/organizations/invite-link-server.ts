// Happy-path stand-ins for the seven endpoints `InviteLinkClient` calls.

import { Routes } from "../http-mock";
import {
  TEST_INVITE,
  TEST_ORGANIZATION_ID,
  TEST_ORG_PUBLIC_KEY,
  TEST_ORG_WRAPPED_PRIVATE_KEY,
} from "../org-fixtures";

const ORG = TEST_ORGANIZATION_ID as unknown as string;

/** Route keys, so tests assert against the same strings the mock matches on. */
export const ROUTES = {
  privateKey: `GET /organizations/${ORG}/private-key`,
  publicKey: `GET /organizations/${ORG}/public-key`,
  create: `POST /organizations/${ORG}/invite-link`,
  refresh: `POST /organizations/${ORG}/invite-link/refresh`,
  getInvite: "POST /organizations/users/invite-link/invite",
  confirm: "POST /organizations/users/invite-link/confirm",
  accept: "POST /organizations/users/invite-link/accept",
} as const;

export const LINK_ID = "1c4d9d5a-0000-4000-8000-000000000001";
export const LINK_CODE = "1c4d9d5a-0000-4000-8000-000000000002";
export const CREATION_DATE = "2024-01-01T00:00:00Z";

export interface InviteLinkServerOptions {
  /**
   * The invite `get_invite` serves to a redeeming invitee. Defaults to {@link TEST_INVITE}.
   * Resolved per request, so it can be a thunk returning an invite created earlier in the test.
   */
  invite?: string | (() => string);
  /** The organization public key, i.e. the account-recovery key an invitee enrolls into. */
  publicKey?: string;
  /** Called with the invite posted to create/refresh, standing in for the server persisting it. */
  onCreate?: (invite: string) => void;
}

/**
 * The full set of happy-path handlers. Spread it and override individual routes per test:
 *
 * ```ts
 * installHttpMock({ ...inviteLinkRoutes(), [ROUTES.getInvite]: () => ({ json: { invite } }) });
 * ```
 *
 * Create and refresh echo the posted invite back in their response, the way the server persists and
 * returns it, so `link.invite` is genuinely what went over the wire.
 */
export function inviteLinkRoutes(options: InviteLinkServerOptions = {}): Routes {
  const invite = () => {
    const configured = options.invite ?? (TEST_INVITE as unknown as string);
    return typeof configured === "function" ? configured() : configured;
  };
  const publicKey = options.publicKey ?? TEST_ORG_PUBLIC_KEY;

  const link = (posted: {
    invite: string;
    supportsConfirmation: boolean;
    allowedDomains?: string[];
  }) => {
    options.onCreate?.(posted.invite);
    return {
      json: {
        object: "organizationInviteLink",
        id: LINK_ID,
        code: LINK_CODE,
        organizationId: ORG,
        allowedDomains: posted.allowedDomains ?? [],
        invite: posted.invite,
        supportsConfirmation: posted.supportsConfirmation,
        creationDate: CREATION_DATE,
      },
    };
  };

  return {
    [ROUTES.privateKey]: () => ({
      json: { object: "organizationPrivateKey", privateKey: TEST_ORG_WRAPPED_PRIVATE_KEY },
    }),
    [ROUTES.publicKey]: () => ({ json: { object: "organizationPublicKey", publicKey } }),
    [ROUTES.create]: (request) => link(request.json()),
    [ROUTES.refresh]: (request) => link(request.json()),
    [ROUTES.getInvite]: () => ({ json: { invite: invite() } }),
    [ROUTES.confirm]: () => ({}),
    [ROUTES.accept]: () => ({}),
  };
}
