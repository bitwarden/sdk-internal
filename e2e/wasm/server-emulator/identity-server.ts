// An in-memory model of the identity service, which issues and refreshes access tokens.

import type { Database } from "./database";
import {
  OAuth2ErrorResponse,
  PasswordPreloginRequest,
  PasswordPreloginResponse,
  TokenResponse,
} from "./dto";
import type { MockReply, Routes } from "./http-mock";
import type { AccountId, UserEntity } from "./entities";
import { HTTP_BAD_REQUEST, HTTP_NOT_FOUND } from "./replies";

/** The OAuth2 grant types the token endpoint answers. */
const GRANT_TYPE_PASSWORD = "password";

export class IdentityServer {
  constructor(private readonly db: Database) {}

  routes(): Routes {
    return {
      "POST /accounts/prelogin/password": (request) =>
        this.prelogin(request.json<PasswordPreloginRequest>()),

      // Form-encoded per the OAuth2 spec, so this route reads the raw body rather than JSON.
      "POST /connect/token": (request) => this.token(new URLSearchParams(request.body)),
    };
  }

  /**
   * The KDF and salt a client needs before it can derive its master key.
   *
   * Unauthenticated, as it must be: a client has no token until it has authenticated, and cannot
   * authenticate without knowing how to derive its hash.
   */
  private prelogin(posted: PasswordPreloginRequest): MockReply {
    const user = this.userFor(posted.email);
    if (user === undefined) {
      return oauth2Error(HTTP_NOT_FOUND, "invalid_request", `no account for ${posted.email}`);
    }

    return { json: PasswordPreloginResponse.fromUser(user, posted.email) };
  }

  /**
   * Issues an access token for an account that proved possession of its master password.
   *
   * The account's expected authentication hash is data the emulator holds, not something it
   * derives: the real server never sees a password either.
   */
  private token(form: URLSearchParams): MockReply {
    const grantType = form.get("grant_type");
    if (grantType !== GRANT_TYPE_PASSWORD) {
      return oauth2Error(HTTP_BAD_REQUEST, "unsupported_grant_type", `grant type ${grantType}`);
    }

    const user = this.userFor(form.get("username") ?? "");
    const hash = form.get("password");
    if (user === undefined || hash === null || hash !== user.masterPasswordAuthenticationHash) {
      return oauth2Error(HTTP_BAD_REQUEST, "invalid_grant", "invalid_username_or_password");
    }

    this.registerDevice(user.userId, form.get("deviceIdentifier"));
    return { json: TokenResponse.forUser(user, this.issueToken(user.email)) };
  }

  /**
   * An access token for an account, without going through the password grant.
   *
   * For a test that drives an account real login cannot reach. A client against a real server has
   * no equivalent, so this is emulator-only. The account may be one that has no keys yet. A device
   * identifier registers the device, as an SSO login does.
   */
  issueToken(email: string, deviceIdentifier?: string): string {
    const [pending] = this.db.pendingAccounts.filter((candidate) => candidate.email === email);
    const userId = this.userFor(email)?.userId ?? pending?.userId;
    if (userId === undefined) {
      throw new Error(`no seeded account with email ${email}`);
    }

    if (deviceIdentifier !== undefined) {
      this.registerDevice(userId, deviceIdentifier);
    }

    const token = this.db.sessions.newId();
    this.db.sessions.set(token, userId);

    return token;
  }

  /** Records the device a login came from, once per user and identifier. */
  private registerDevice(userId: AccountId, identifier: string | null): void {
    if (identifier === null) {
      return;
    }

    const known = this.db.devices.filter(
      (device) => device.userId === userId && device.identifier === identifier,
    );
    if (known.length > 0) {
      return;
    }

    this.db.devices.set(this.db.devices.newId(), {
      userId,
      identifier,
      encryptedUserKey: null,
      encryptedPublicKey: null,
      encryptedPrivateKey: null,
      lostTrustReported: false,
    });
  }

  private userFor(email: string): UserEntity | undefined {
    const [user] = this.db.users.filter((candidate) => candidate.email === email);

    return user;
  }
}

function oauth2Error(status: number, code: string, description: string): MockReply {
  const body: OAuth2ErrorResponse = { error: code, error_description: description };

  return { status, json: body };
}
