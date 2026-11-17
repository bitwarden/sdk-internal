// Happy-path stand-ins for the endpoints `OrganizationCreateClient` calls.

import { MockReply, Routes } from "../../server-emulator/http-mock";

/** Route keys, so tests assert against the same strings the mock matches on. */
export const ROUTES = {
  createWithoutPayment: "POST /organizations/create-without-payment",
  create: "POST /organizations",
  providerClientCreate: (providerId: string) => `POST /providers/${providerId}/clients`,
} as const;

/**
 * The happy-path handler for a create endpoint: returns a fresh organization id and, for routes
 * whose response model carries one, echoes it back as `id`.
 */
function created(organizationId: string): MockReply {
  return { json: { object: "organization", id: organizationId } };
}

export interface OrganizationCreateServerOptions {
  /** The organization id every create route hands back. */
  organizationId?: string;
}

/**
 * The full set of happy-path handlers for `Free`/`Paid`/`Trial` organization creation. Spread it
 * and override individual routes per test:
 *
 * ```ts
 * installHttpMock({ ...organizationCreateRoutes(), [ROUTES.create]: () => ({ status: 400 }) });
 * ```
 */
export function organizationCreateRoutes(options: OrganizationCreateServerOptions = {}): Routes {
  const organizationId = options.organizationId ?? "2c4d9d5a-0000-4000-8000-000000000001";

  return {
    [ROUTES.createWithoutPayment]: () => created(organizationId),
    [ROUTES.create]: () => created(organizationId),
  };
}

/**
 * The happy-path handler for `ProviderClient` organization creation, bound to one provider id.
 * `POST /providers/{providerId}/clients` returns no body on success.
 */
export function providerClientCreateRoutes(providerId: string): Routes {
  return {
    [ROUTES.providerClientCreate(providerId)]: () => ({}),
  };
}
