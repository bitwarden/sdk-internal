// An in-memory model of the identity service, which issues and refreshes access tokens.

import type { WrappedAccountCryptographicState } from "@bitwarden/sdk-internal";

import {
  asAccountId,
  asEncString,
  asKeyId,
  asSignedPublicKey,
  asSignedSecurityState,
} from "../tests/type-assertion-helpers";

import type { Database } from "./database";
import {
  MasterPasswordUnlockDataModel,
  OAuth2ErrorResponse,
  PasswordPreloginRequest,
  PasswordPreloginResponse,
  TokenResponse,
  type AccountKeysRequest,
  type RegisterFinishRequest,
  type RegisterSendVerificationEmailRequest,
} from "./dto";
import type { MockReply, Routes } from "./http-mock";
import type { UserEntity } from "./entities";
import { error, HTTP_BAD_REQUEST, HTTP_NOT_FOUND } from "./replies";

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

      "POST /accounts/register/send-verification-email": (request) =>
        this.sendVerificationEmail(request.json<RegisterSendVerificationEmailRequest>()),

      "POST /accounts/register/finish": (request) =>
        this.registerFinish(request.json<RegisterFinishRequest>()),
    };
  }

  /**
   * Starts a registration, answering with the email-verification token.
   *
   * A real server answers this way only with email verification turned off; with it on, it mails
   * the token and answers 204. The emulator sends no mail, so it always answers with the token.
   */
  private sendVerificationEmail(posted: RegisterSendVerificationEmailRequest): MockReply {
    const token = this.db.emailVerificationTokens.newId();
    this.db.emailVerificationTokens.set(token, posted.email);

    return { json: token };
  }

  /**
   * Creates an account from what the client generated, as the email-verification token allows.
   *
   * The server receives only Protected Data: the keys arrive wrapped, and the master password only
   * as its authentication hash.
   */
  private registerFinish(posted: RegisterFinishRequest): MockReply {
    const token = posted.emailVerificationToken;
    if (token === undefined || token === null) {
      return error(HTTP_BAD_REQUEST, "email verification token required");
    }
    if (this.db.emailVerificationTokens.get(token) !== posted.email) {
      return error(HTTP_BAD_REQUEST, "invalid email verification token");
    }
    if (this.userFor(posted.email) !== undefined) {
      return error(HTTP_BAD_REQUEST, `email ${posted.email} is already taken`);
    }

    const keys = posted.accountKeys;
    const pair = keys.publicKeyEncryptionKeyPair;
    const unlock = MasterPasswordUnlockDataModel.toStored(posted.masterPasswordUnlock);

    const user: UserEntity = {
      userId: asAccountId(this.db.users.newId()),
      email: posted.email,
      accountCryptographicState: accountStateOf(keys),
      publicKey: pair?.publicKey ?? keys.accountPublicKey,
      verifyingKey: keys.signatureKeyPair?.verifyingKey ?? null,
      securityVersion: keys.securityState?.securityVersion,
      kdf: unlock.kdf,
      userKeyId: unlock.containedKeyId ? asKeyId(unlock.containedKeyId) : undefined,
      masterPasswordUnlock: unlock,
      masterPasswordAuthenticationHash:
        posted.masterPasswordAuthentication.masterPasswordAuthenticationHash,
      organizationKeys: {},
    };

    this.db.emailVerificationTokens.remove(token);
    this.db.users.set(user.userId, user);

    return { json: {} };
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

    return { json: TokenResponse.forUser(user, this.issueToken(user.email)) };
  }

  /**
   * An access token for an account, without going through the password grant.
   *
   * For a test that drives an account real login cannot reach. A client against a real server has
   * no equivalent, so this is emulator-only.
   */
  issueToken(email: string): string {
    const user = this.userFor(email);
    if (user === undefined) {
      throw new Error(`no seeded account with email ${email}`);
    }

    const token = this.db.sessions.newId();
    this.db.sessions.set(token, user.userId);

    return token;
  }

  private userFor(email: string): UserEntity | undefined {
    const [user] = this.db.users.filter((candidate) => candidate.email === email);

    return user;
  }
}

/** The account state registration posted: V2 when it carries a signature key pair, else V1. */
function accountStateOf(keys: AccountKeysRequest): WrappedAccountCryptographicState {
  const pair = keys.publicKeyEncryptionKeyPair;
  const { signatureKeyPair, securityState } = keys;

  if (!signatureKeyPair || !securityState || !pair?.signedPublicKey) {
    return { V1: { private_key: asEncString(keys.userKeyEncryptedAccountPrivateKey) } };
  }

  return {
    V2: {
      private_key: asEncString(pair.wrappedPrivateKey),
      signing_key: asEncString(signatureKeyPair.wrappedSigningKey),
      security_state: asSignedSecurityState(securityState.securityState),
      signed_public_key: asSignedPublicKey(pair.signedPublicKey),
    },
  };
}

function oauth2Error(status: number, code: string, description: string): MockReply {
  const body: OAuth2ErrorResponse = { error: code, error_description: description };

  return { status, json: body };
}
