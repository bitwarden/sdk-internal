// Who a request is from, shared by every service that reads the same bearer token.

import type { Database } from "./database";
import type { PendingAccountEntity, UserEntity } from "./entities";
import { bearerToken, type MockReply, type MockRequest, type RouteHandler } from "./http-mock";
import { error, HTTP_UNAUTHORIZED } from "./replies";

/** Either the account the request authenticated as, or the reply to send instead. */
export type Authenticated = { user: UserEntity } | { reply: MockReply };

export function authenticate(db: Database, request: MockRequest): Authenticated {
  const token = bearerToken(request);
  if (token === undefined) {
    return { reply: error(HTTP_UNAUTHORIZED, `no bearer token on ${request.route}`) };
  }

  const userId = db.sessions.get(token);
  if (userId === undefined) {
    return { reply: error(HTTP_UNAUTHORIZED, `bearer token ${token} was never issued`) };
  }

  const user = db.users.get(userId);
  if (user === undefined) {
    return { reply: error(HTTP_UNAUTHORIZED, `token ${token} authenticates no seeded account`) };
  }

  return { user };
}

/** Wraps a handler that needs an authenticated caller, answering 401 when there is none. */
export function authenticatedRoute(
  db: Database,
  handler: (user: UserEntity, request: MockRequest) => MockReply | Promise<MockReply>,
): RouteHandler {
  return (request) => {
    const authenticated = authenticate(db, request);
    if ("reply" in authenticated) {
      return authenticated.reply;
    }

    return handler(authenticated.user, request);
  };
}

/**
 * Wraps a handler for an account that is authenticated but has no keys yet, answering 401 when the
 * token names no such account.
 */
export function pendingAccountRoute(
  db: Database,
  handler: (account: PendingAccountEntity, request: MockRequest) => MockReply | Promise<MockReply>,
): RouteHandler {
  return (request) => {
    const token = bearerToken(request);
    const userId = token === undefined ? undefined : db.sessions.get(token);
    const account = userId === undefined ? undefined : db.pendingAccounts.get(userId);
    if (account === undefined) {
      return error(HTTP_UNAUTHORIZED, `no keyless account behind the token on ${request.route}`);
    }

    return handler(account, request);
  };
}
