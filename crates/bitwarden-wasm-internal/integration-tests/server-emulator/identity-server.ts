// An in-memory model of the identity service, which issues and refreshes access tokens.

import type { Database } from "./database";
import {
  OAuth2ErrorResponse,
  MasterPasswordUnlockDataModel,
  PasswordPreloginRequest,
  PasswordPreloginResponse,
  RegisterFinishRequest,
  toKdf,
  TokenResponse,
} from "./dto";
import type { MockReply, Routes } from "./http-mock";
import {
  asEncString,
  asSignedPublicKey,
  asSignedSecurityState,
} from "../tests/type-assertion-helpers";
import type { UserEntity } from "./entities";
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

      "POST /accounts/register/finish": (request) =>
        this.registerFinish(request.json<RegisterFinishRequest>()),
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

    return { json: PasswordPreloginResponse.fromUser(user) };
  }

  /**
   * Issues an access token for an account that proved its master password.
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

    return { json: TokenResponse.forUser(user) };
  }

  /**
   * Creates an account from the key material a client generated for it.
   *
   * This is the only route that creates an account rather than reading a seeded one, so the
   * registered account has to be complete enough for a later login and unlock to work off it.
   */
  private registerFinish(posted: RegisterFinishRequest): MockReply {
    if (this.userFor(posted.email) !== undefined) {
      return oauth2Error(HTTP_BAD_REQUEST, "invalid_request", `${posted.email} already registered`);
    }

    const {
      publicKeyEncryptionKeyPair: pair,
      signatureKeyPair,
      securityState,
    } = posted.accountKeys;
    if (pair === undefined || signatureKeyPair === undefined || securityState === undefined) {
      return oauth2Error(HTTP_BAD_REQUEST, "invalid_request", "incomplete account keys");
    }
    if (pair.signedPublicKey === undefined) {
      return oauth2Error(HTTP_BAD_REQUEST, "invalid_request", "a V2 key pair must be signed");
    }

    const userId = this.db.users.newId();
    this.db.users.set(userId, {
      userId,
      email: posted.email,
      accountCryptographicState: {
        V2: {
          private_key: asEncString(pair.wrappedPrivateKey),
          signing_key: asEncString(signatureKeyPair.wrappedSigningKey),
          security_state: asSignedSecurityState(securityState.securityState),
          signed_public_key: asSignedPublicKey(pair.signedPublicKey),
        },
      },
      publicKey: pair.publicKey,
      verifyingKey: signatureKeyPair.verifyingKey,
      securityVersion: securityState.securityVersion,
      kdf: toKdf(posted.masterPasswordUnlock.kdf),
      masterPasswordUnlock: MasterPasswordUnlockDataModel.toStored(posted.masterPasswordUnlock),
      masterPasswordAuthenticationHash:
        posted.masterPasswordAuthentication.masterPasswordAuthenticationHash,
      organizationKeys: {},
    });

    return { json: { object: "register" } };
  }

  /** The seeded account with this email, addressed as the rest of the harness does. */
  private userFor(email: string): UserEntity | undefined {
    const [user] = this.db.users.filter((candidate) => candidate.email === email);

    return user;
  }
}

function oauth2Error(status: number, code: string, description: string): MockReply {
  const body: OAuth2ErrorResponse = { error: code, error_description: description };

  return { status, json: body };
}
