// The identity server's prelogin and token models.

import type { UserEntity } from "../entities";
import { AccountKeysResponse } from "./account-keys";
import { KdfModel, KdfType, type KdfTypeValue } from "./kdf";
import { MasterPasswordUnlockResponse } from "./master-password";

/** How long an issued access token stays valid, as the identity service reports it. */
const TOKEN_LIFETIME_SECONDS = 3600;

/** `PasswordPreloginRequestModel` — the body of `POST /accounts/prelogin/password`. */
export class PasswordPreloginRequest {
  email!: string;
}

/** The server's default PBKDF2 iteration count. */
const DEFAULT_PBKDF2_ITERATIONS = 600_000;

/** `PasswordPreloginResponseModel`. */
export class PasswordPreloginResponse {
  // PM-28143: legacy flat KDF fields, removed with the cleanup
  kdf?: KdfTypeValue;
  kdfIterations?: number;
  kdfMemory?: number;
  kdfParallelism?: number;

  kdfSettings?: KdfModel;
  salt?: string;

  /** The server echoes the request email as salt until PM-28143. */
  static fromUser(user: UserEntity, email: string): PasswordPreloginResponse {
    const kdfSettings = KdfModel.fromKdf(user.kdf);

    return PasswordPreloginResponse.fromKdf(kdfSettings, email);
  }

  /**
   * The answer for an address with no account. The server answers rather than refusing, so that
   * prelogin can't tell which addresses have accounts; this is the default it most often gives.
   */
  static forUnknownEmail(email: string): PasswordPreloginResponse {
    return PasswordPreloginResponse.fromKdf(
      { kdfType: KdfType.pbkdf2Sha256, iterations: DEFAULT_PBKDF2_ITERATIONS },
      email,
    );
  }

  private static fromKdf(kdfSettings: KdfModel, email: string): PasswordPreloginResponse {
    return {
      kdf: kdfSettings.kdfType,
      kdfIterations: kdfSettings.iterations,
      kdfMemory: kdfSettings.memory,
      kdfParallelism: kdfSettings.parallelism,
      kdfSettings,
      salt: email,
    };
  }
}

/** `LoginSuccessResponseModel`. The access token is the user id, as other services expect. */
export class TokenResponse {
  access_token!: string;
  expires_in!: number;
  token_type!: string;
  scope!: string;
  Key?: string;
  PrivateKey?: string;
  AccountKeys?: AccountKeysResponse;
  UserDecryptionOptions!: { MasterPasswordUnlock?: MasterPasswordUnlockResponse };

  static forUser(user: UserEntity, accessToken: string): TokenResponse {
    const unlock = user.masterPasswordUnlock;

    return {
      access_token: accessToken,
      expires_in: TOKEN_LIFETIME_SECONDS,
      token_type: "Bearer",
      scope: "api offline_access",
      Key: unlock?.masterKeyWrappedUserKey,
      PrivateKey: AccountKeysResponse.wrappedPrivateKeyOf(user),
      AccountKeys: AccountKeysResponse.fromUser(user),
      UserDecryptionOptions: {
        MasterPasswordUnlock: unlock ? MasterPasswordUnlockResponse.fromStored(unlock) : undefined,
      },
    };
  }
}

/** OAuth2 error, as the token endpoint answers. */
export class OAuth2ErrorResponse {
  error!: string;
  error_description!: string;
}
