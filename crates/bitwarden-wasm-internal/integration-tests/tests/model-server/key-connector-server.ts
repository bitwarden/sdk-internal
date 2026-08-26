// A model of a key connector, kept deliberately separate from the API model.
//
// It is a key-value store for exactly one key per user, and its only interesting behaviour is that it
// has no upsert: a client must read first and then choose POST (create) or PUT (update). Modelling the
// "no key yet" case as a 404 is what makes that choice observable, and it is why this is a state
// machine rather than three fixed handlers.
//
// It lives on its own origin so a request meant for the API can never be answered here by accident.

import type { MockReply, MockRequest, Routes } from "../http-mock";

export class KeyConnectorServer {
  private stored: string | undefined;
  private writeFailure: number | undefined;

  /** The route table to install. */
  routes(): Routes {
    return {
      // A connector with no key for this user answers 404, which is what selects POST over PUT.
      "GET /user-keys": () =>
        this.stored === undefined
          ? { status: 404, json: { message: "no key for user" } }
          : { json: { key: this.stored } },
      "POST /user-keys": (request) => this.write("create", request),
      "PUT /user-keys": (request) => this.write("update", request),
    };
  }

  /** The key currently stored, base64, or `undefined` if the connector holds none. */
  key(): string | undefined {
    return this.stored;
  }

  /** Pre-loads a key, so the next migration takes the PUT branch. */
  seedKey(key: string): void {
    this.stored = key;
  }

  /** Makes writes fail, for testing that the caller aborts before enrolling server-side. */
  failWrites(status: number): void {
    this.writeFailure = status;
  }

  /**
   * A write, with the verb constraint the real connector imposes.
   *
   * `create` may only be used when no key exists and `update` only when one does — which is the whole
   * reason a client has to read before it writes. Enforcing it here means a client that picked the wrong
   * verb fails the migration outright, so no test has to inspect which route was called to find out.
   */
  private write(mode: "create" | "update", request: MockRequest): MockReply {
    if (this.writeFailure !== undefined) {
      return { status: this.writeFailure, json: { message: "key connector unavailable" } };
    }
    if (mode === "create" && this.stored !== undefined) {
      return { status: 409, json: { message: "a key already exists; use PUT" } };
    }
    if (mode === "update" && this.stored === undefined) {
      return { status: 404, json: { message: "no key to update; use POST" } };
    }
    this.stored = request.json<{ key: string }>().key;
    return {};
  }
}
