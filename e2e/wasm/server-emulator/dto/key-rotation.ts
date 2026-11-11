// The request and response models of user-key rotation, KDF changes and key ids.

import {
  PublicKeyEncryptionKeyPairRequest,
  SecurityStateRequest,
  SignatureKeyPairRequest,
  WrappedAccountCryptographicStateRequest,
} from "./account-keys";
import { KdfModel, type KdfTypeValue } from "./kdf";
import {
  MasterPasswordAuthenticationDataModel,
  MasterPasswordUnlockDataModel,
} from "./master-password";
import { V2UpgradeTokenResponse } from "./sync";
import { CipherRequest } from "./vault";

/** The server's numeric `UnlockMethod`. */
export const UnlockMethod = { tde: 0, masterPassword: 1, keyConnector: 2 } as const;
export type UnlockMethodValue = (typeof UnlockMethod)[keyof typeof UnlockMethod];

/** `UnlockMethodRequestModel` — how the rotated user key is wrapped for the primary unlock. */
export class UnlockMethodRequest {
  unlockMethod!: UnlockMethodValue;
  masterPasswordUnlockData?: MasterPasswordUnlockDataModel;
  keyConnectorKeyWrappedUserKey?: string;
}

/** `CommonUnlockDataRequestModel` — the unlock paths a rotation re-wraps for. */
export class CommonUnlockDataRequest {
  emergencyAccessUnlockData!: unknown[] | null;
  organizationAccountRecoveryUnlockData!: unknown[] | null;
  passkeyUnlockData!: unknown[] | null;
  deviceKeyUnlockData!: unknown[] | null;
  v2UpgradeToken?: V2UpgradeTokenResponse;
}

/** `AccountDataRequestModel` — the vault, re-encrypted under the new user key. */
export class AccountDataRequest {
  ciphers?: (CipherRequest & { id: string })[] | null;
  folders?: { id: string; name: string }[] | null;
  sends?: unknown[] | null;
}

/**
 * `KeyRegenerationRequestModel` — the body of `POST /accounts/key-management/regenerate-keys`.
 */
export class KeyRegenerationRequest {
  userPublicKey!: string;
  userKeyEncryptedUserPrivateKey!: string;
}

/** `RotateUserKeysRequestModel` — the body of `POST /accounts/key-management/rotate-user-keys`. */
export class RotateUserKeysRequest {
  wrappedAccountCryptographicState!: WrappedAccountCryptographicStateRequest;
  unlockData!: CommonUnlockDataRequest;
  accountData!: AccountDataRequest;
  unlockMethodData!: UnlockMethodRequest;
  newUserKeyId?: string;
}

/** `AccountKeysRequestModel` — a V1 account omits the signature key pair and security state. */
export class AccountKeysRequest {
  publicKeyEncryptionKeyPair!: PublicKeyEncryptionKeyPairRequest;
  signatureKeyPair?: SignatureKeyPairRequest | null;
  securityState?: SecurityStateRequest | null;
}

/** `MasterPasswordUnlockAndAuthenticationDataModel` — the new password, KDF fields flattened. */
export class MasterPasswordUnlockAndAuthenticationDataModel {
  kdfType!: KdfTypeValue;
  kdfIterations!: number;
  kdfMemory?: number | null;
  kdfParallelism?: number | null;
  masterKeyAuthenticationHash!: string;
  masterKeyEncryptedUserKey!: string;
  masterPasswordHint?: string | null;
  masterPasswordSalt!: string;
  containedKeyId?: string | null;

  /** The KDF the new password is derived with. */
  static kdfOf(posted: MasterPasswordUnlockAndAuthenticationDataModel): KdfModel {
    return {
      kdfType: posted.kdfType,
      iterations: posted.kdfIterations,
      memory: posted.kdfMemory ?? undefined,
      parallelism: posted.kdfParallelism ?? undefined,
    };
  }
}

/** `UnlockDataRequestModel` — {@link CommonUnlockDataRequest} plus the new master password. */
export class UnlockDataRequest extends CommonUnlockDataRequest {
  masterPasswordUnlockData!: MasterPasswordUnlockAndAuthenticationDataModel;
}

/**
 * `RotateUserAccountKeysAndDataRequestModel` — the body of
 * `POST /accounts/key-management/rotate-user-account-keys`, a rotation bundled with a password
 * change.
 */
export class RotateUserAccountKeysAndDataRequest {
  oldMasterKeyAuthenticationHash!: string;
  accountUnlockData!: UnlockDataRequest;
  accountKeys!: AccountKeysRequest;
  accountData!: AccountDataRequest;
  newUserKeyId?: string | null;
}

/**
 * `KeyRotationDataResponseModel` — everything a rotation has to re-wrap the new user key for.
 *
 * Every array is required: `key_rotation/sync.rs` maps an absent one to `SyncError::Data`, so an
 * omitted field fails the rotation rather than reading as "none".
 */
export class KeyRotationDataResponse {
  organizationPasswordResetKeyData!: unknown[];
  emergencyAccessKeyData!: unknown[];
  trustedDeviceKeyData!: unknown[];
  passkeyKeyData!: unknown[];

  /** An account with no organizations, grantees, trusted devices or passkeys. */
  static empty(): KeyRotationDataResponse {
    return {
      organizationPasswordResetKeyData: [],
      emergencyAccessKeyData: [],
      trustedDeviceKeyData: [],
      passkeyKeyData: [],
    };
  }
}

/** The body of `POST /accounts/key-management/user-key-id`. */
export class UserKeyIdRequest {
  userKeyId!: string;
}

export class ChangeKdfRequest {
  /** Proof of possession, hashed under the *old* KDF. */
  masterPasswordHash!: string;
  authenticationData!: MasterPasswordAuthenticationDataModel;
  unlockData!: MasterPasswordUnlockDataModel;
}
