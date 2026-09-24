// An in-memory model of key connector, which holds a key-connector key on each account's behalf.
//
// A deployment serves the members of one organization, so the model holds one key per account and
// identifies the caller from the same bearer token the api server reads. An account can only ever
// reach its own key.

import { authenticatedRoute } from "./authentication";
import type { Database } from "./database";
import type { MockReply, Routes } from "./http-mock";
import { error, HTTP_NOT_FOUND } from "./replies";

/** The body of `GET /user-keys`, and the one `POST /user-keys` takes. */
export interface UserKeyBody {
  key: string;
}

export class KeyConnectorServer {
  /** The stored key-connector key per account, by user id. */
  private readonly keyConnectorKeys = new Map<string, string>();

  constructor(private readonly db: Database) {}

  /** Seeds the key an account reads back, as a deployment that already knows the account. */
  seedUserKey(email: string, key: string): void {
    this.keyConnectorKeys.set(this.userIdFor(email), key);
  }

  /** The key stored for an account, for assertions. `null` when it has none. */
  storedUserKey(email: string): string | null {
    return this.keyConnectorKeys.get(this.userIdFor(email)) ?? null;
  }

  routes(): Routes {
    return {
      "GET /user-keys": authenticatedRoute(this.db, (user) => this.getUserKey(user.userId)),
      "POST /user-keys": authenticatedRoute(this.db, (user, request) =>
        this.setUserKey(user.userId, request.json<UserKeyBody>()),
      ),
    };
  }

  private getUserKey(userId: string): MockReply {
    const key = this.keyConnectorKeys.get(userId);
    if (key === undefined) {
      return error(HTTP_NOT_FOUND, `no key-connector key stored for ${userId}`);
    }

    const body: UserKeyBody = { key };
    return { json: body };
  }

  private setUserKey(userId: string, posted: UserKeyBody): MockReply {
    this.keyConnectorKeys.set(userId, posted.key);

    return {};
  }

  /** Addresses accounts by email, as the rest of the harness does. */
  private userIdFor(email: string): string {
    const [user] = this.db.users.filter((candidate) => candidate.email === email);
    if (user === undefined) {
      throw new Error(`no seeded account with email ${email}`);
    }

    return user.userId;
  }
}
