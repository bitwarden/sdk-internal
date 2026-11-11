// `GET /sync`'s response and the models only it serves.

import type { Cipher, Folder } from "@bitwarden/sdk-internal";

import type { UserEntity } from "../entities";
import { AccountKeysResponse } from "./account-keys";
import { MasterPasswordUnlockResponse } from "./master-password";
import { CipherResponse, FolderResponse } from "./vault";

/** `V2UpgradeTokenResponseModel`. */
export class V2UpgradeTokenResponse {
  wrappedUserKey1!: string;
  wrappedUserKey2!: string;
}

/**
 * `UserDecryptionResponseModel` — how an account can be unlocked, as `GET /sync` reports it.
 *
 * `webAuthnPrfOptions` is omitted until an account vector has any.
 */
export class UserDecryptionResponse {
  /** `null` for an account without a master password. */
  masterPasswordUnlock!: MasterPasswordUnlockResponse | null;
  /** Omitted, not `null`, when absent, as is {@link userKeyId}. */
  v2UpgradeToken?: V2UpgradeTokenResponse;
  userKeyId?: string;

  static fromUser(user: UserEntity): UserDecryptionResponse {
    return {
      masterPasswordUnlock:
        user.masterPasswordUnlock === null
          ? null
          : MasterPasswordUnlockResponse.fromStored(user.masterPasswordUnlock),
      ...(user.upgradeToken === undefined
        ? {}
        : {
            v2UpgradeToken: {
              wrappedUserKey1: String(user.upgradeToken.wrapped_user_key_1),
              wrappedUserKey2: String(user.upgradeToken.wrapped_user_key_2),
            },
          }),
      userKeyId: user.userKeyId ?? undefined,
    };
  }
}

export class KeysResponse {
  object!: "keys";
  key!: string | null;
  publicKey!: string;
  privateKey!: string;
  accountKeys!: AccountKeysResponse;

  static fromUser(user: UserEntity): KeysResponse {
    return {
      object: "keys",
      key:
        user.masterPasswordUnlock === null
          ? null
          : String(user.masterPasswordUnlock.masterKeyWrappedUserKey),
      publicKey: user.publicKey,
      privateKey: AccountKeysResponse.wrappedPrivateKeyOf(user),
      accountKeys: AccountKeysResponse.fromUser(user),
    };
  }
}

/** The subset of `ProfileResponseModel` the SDK reads. */
/**
 * `ProfileOrganizationResponseModel` — one organization the account is a member of.
 *
 * `key` is the organization key sealed to the account's public key, which is the only way a client
 * ever learns it: a member unseals it at unlock and initializes organization crypto from it.
 */
export class ProfileOrganizationResponse {
  object!: "profileOrganization";
  id!: string;
  key!: string;
}

export class ProfileResponse {
  object!: "profile";
  id!: string;
  email!: string;
  key!: string | null;
  privateKey!: string | null;
  securityStamp!: string | null;
  organizations!: ProfileOrganizationResponse[];
  /** The account's cryptographic state, which a rotation reads the current keys from. */
  accountKeys!: AccountKeysResponse;

  static fromUser(user: UserEntity, organizations: ProfileOrganizationResponse[]): ProfileResponse {
    return {
      object: "profile",
      id: user.userId,
      email: user.email,
      key: user.masterPasswordUnlock?.masterKeyWrappedUserKey ?? null,
      privateKey: AccountKeysResponse.wrappedPrivateKeyOf(user),
      securityStamp: null,
      organizations,
      accountKeys: AccountKeysResponse.fromUser(user),
    };
  }
}

export class SyncResponse {
  object!: "sync";
  profile!: ProfileResponse;
  userDecryption!: UserDecryptionResponse;
  folders!: FolderResponse[];
  collections!: [];
  ciphers!: CipherResponse[];
  domains!: null;
  policies!: [];
  sends!: [];

  /** `GET /sync` for one account, over the vault the caller can reach. */
  static forUser(
    user: UserEntity,
    vault: { ciphers: Cipher[]; folders: Folder[] },
    organizations: ProfileOrganizationResponse[],
  ): SyncResponse {
    return {
      object: "sync",
      profile: ProfileResponse.fromUser(user, organizations),
      userDecryption: UserDecryptionResponse.fromUser(user),
      folders: vault.folders.map(FolderResponse.fromFolder),
      collections: [],
      ciphers: vault.ciphers.map(CipherResponse.fromCipher),
      domains: null,
      policies: [],
      sends: [],
    };
  }
}
