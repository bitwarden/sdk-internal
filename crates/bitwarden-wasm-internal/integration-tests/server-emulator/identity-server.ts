// An in-memory model of the identity service, which issues and refreshes access tokens.

import type { Database } from "./database";
import type { Routes } from "./http-mock";

export class IdentityServer {
  constructor(private readonly db: Database) {}

  routes(): Routes {
    return {};
  }
}
