// Who a request is from, shared by every service that reads the same bearer token.

import type { Database } from "./database";
import type { UserEntity } from "./entities";
import { bearerToken, type MockReply, type MockRequest, type RouteHandler } from "./http-mock";
import { error, HTTP_UNAUTHORIZED } from "./replies";

/** Either the account the request authenticated as, or the reply to send instead. */
export type Authenticated = { user: UserEntity } | { reply: MockReply };

export function authenticate(db: Database, request: MockRequest): Authenticated {
  const token = bearerToken(request);
  if (token === undefined) {
    return { reply: error(HTTP_UNAUTHORIZED, `no bearer token on ${request.route}`) };
  }

  const user = db.users.get(token);
  if (user === undefined) {
    return { reply: error(HTTP_UNAUTHORIZED, `bearer token ${token} is not a seeded account`) };
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
