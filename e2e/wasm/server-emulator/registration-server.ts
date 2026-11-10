// An in-memory model of how an account comes and goes: registration on the identity service, and
// deletion on the api service.

import type { WrappedAccountCryptographicState } from "@bitwarden/sdk-internal";

import {
  asAccountId,
  asEncString,
  asKeyId,
  asSignedPublicKey,
  asSignedSecurityState,
} from "../tests/type-assertion-helpers";

import { authenticatedRoute } from "./authentication";
import type { Database } from "./database";
import { MasterPasswordUnlockDataModel } from "./dto/master-password";
import type {
  AccountKeysRequest,
  RegisterFinishRequest,
  RegisterSendVerificationEmailRequest,
  SecretVerificationRequest,
} from "./dto/registration";
import type { UserEntity } from "./entities";
import type { MockReply, Routes } from "./http-mock";
import type { IdentityServer } from "./identity-server";
import { error, HTTP_BAD_REQUEST } from "./replies";

export class RegistrationServer {
  constructor(
    private readonly db: Database,
    private readonly identity: IdentityServer,
  ) {}

  /** The routes the identity service serves. */
  identityRoutes(): Routes {
    return {
      "POST /accounts/register/send-verification-email": (request) =>
        this.sendVerificationEmail(request.json<RegisterSendVerificationEmailRequest>()),

      "POST /accounts/register/finish": (request) =>
        this.registerFinish(request.json<RegisterFinishRequest>()),
    };
  }

  /** The routes the api service serves. */
  apiRoutes(): Routes {
    return {
      "DELETE /accounts": authenticatedRoute(this.db, (user, request) =>
        this.deleteAccount(user, request.json<SecretVerificationRequest>()),
      ),
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
    if (this.identity.userFor(posted.email) !== undefined) {
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
   * Deletes an account that proved possession of its master password, with its vault and sessions.
   */
  private deleteAccount(user: UserEntity, posted: SecretVerificationRequest): MockReply {
    if (
      !posted.masterPasswordHash ||
      posted.masterPasswordHash !== user.masterPasswordAuthenticationHash
    ) {
      return error(HTTP_BAD_REQUEST, "invalid master password hash");
    }

    this.db.removeUser(user.userId);

    return {};
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
