import type {
  Attachment,
  BankAccount,
  Card,
  Cipher,
  CipherPermissions,
  CipherRepromptType,
  CipherType,
  DriversLicense,
  Field,
  Folder,
  Identity,
  Kdf,
  Login,
  PasswordHistory,
  Passport,
  SecureNote,
  SshKey,
  WrappedAccountCryptographicState,
} from "@bitwarden/sdk-internal";

import {
  asCipherId,
  asCollectionId,
  asEncString,
  asFolderId,
  asOrganizationId,
  asSignedPublicKey,
  asSignedSecurityState,
  asString,
} from "../tests/type-assertion-helpers";

import type { StoredMasterPasswordUnlock, UserEntity } from "./entities";

/** The server's numeric `KdfType`. */
export const KdfType = { pbkdf2Sha256: 0, argon2id: 1 } as const;
export type KdfTypeValue = (typeof KdfType)[keyof typeof KdfType];

function optionalString(value: { toString(): string } | null | undefined): string | null {
  return value === null || value === undefined ? null : String(value);
}

function optionalEnc(value: string | null | undefined) {
  return value === null || value === undefined ? undefined : asEncString(value);
}

export class KdfModel {
  kdfType!: KdfTypeValue;
  iterations!: number;
  memory?: number;
  parallelism?: number;

  static fromKdf(kdf: Kdf): KdfModel {
    if ("pBKDF2" in kdf) {
      return { kdfType: KdfType.pbkdf2Sha256, iterations: kdf.pBKDF2.iterations };
    } else {
      return {
        kdfType: KdfType.argon2id,
        iterations: kdf.argon2id.iterations,
        memory: kdf.argon2id.memory,
        parallelism: kdf.argon2id.parallelism,
      };
    }
  }
}

export function toKdf(kdf: KdfModel): Kdf {
  if (kdf.kdfType === KdfType.pbkdf2Sha256) {
    return { pBKDF2: { iterations: kdf.iterations } };
  }

  if (kdf.kdfType === KdfType.argon2id) {
    if (kdf.memory === undefined || kdf.parallelism === undefined) {
      throw new Error(`argon2id kdf without memory or parallelism: ${JSON.stringify(kdf)}`);
    }

    return {
      argon2id: { iterations: kdf.iterations, memory: kdf.memory, parallelism: kdf.parallelism },
    };
  }

  throw new Error(`unrecognised kdf: ${JSON.stringify(kdf)}`);
}

export class MasterPasswordAuthenticationDataModel {
  kdf!: KdfModel;
  masterPasswordAuthenticationHash!: string;
  salt!: string;
}

export class MasterPasswordUnlockDataModel {
  kdf!: KdfModel;
  masterKeyWrappedUserKey!: string;
  salt!: string;
  containedKeyId?: string;

  static toStored(posted: MasterPasswordUnlockDataModel): StoredMasterPasswordUnlock {
    return {
      masterKeyWrappedUserKey: asEncString(posted.masterKeyWrappedUserKey),
      salt: posted.salt,
      kdf: toKdf(posted.kdf),
      ...(posted.containedKeyId === undefined ? {} : { containedKeyId: posted.containedKeyId }),
    };
  }
}

/** `PublicKeyEncryptionKeyPairRequestModel`, as a rotation posts it. */
export class PublicKeyEncryptionKeyPairRequest {
  wrappedPrivateKey!: string;
  publicKey!: string;
  signedPublicKey?: string;
}

/** `SignatureKeyPairRequestModel`. */
export class SignatureKeyPairRequest {
  signatureAlgorithm!: number;
  wrappedSigningKey!: string;
  verifyingKey!: string;
}

/** `SecurityStateModel`. */
export class SecurityStateRequest {
  securityState!: string;
  securityVersion!: number;
}

/**
 * `WrappedAccountCryptographicStateRequestModel` — always the V2 shape.
 */
export class WrappedAccountCryptographicStateRequest {
  publicKeyEncryptionKeyPair!: PublicKeyEncryptionKeyPairRequest;
  signatureKeyPair!: SignatureKeyPairRequest;
  securityState!: SecurityStateRequest;
}

/** `UnlockMethodRequestModel` — how the rotated user key is wrapped for the primary unlock. */
export class UnlockMethodRequest {
  unlockMethod!: "MasterPassword" | "KeyConnector" | "Tde";
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
 *
 * A V1 account whose stored public key does not match its private key gets a fresh key pair before
 * a rotation, so a corrupt pair cannot block one.
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

export class PublicKeyEncryptionKeyPairResponse {
  object!: "publicKeyEncryptionKeyPair";
  wrappedPrivateKey!: string;
  publicKey!: string;
  signedPublicKey?: string;
}

export class SignatureKeyPairResponse {
  object!: "signatureKeyPair";
  wrappedSigningKey!: string;
  verifyingKey!: string;
}

export class SecurityStateResponse {
  securityState!: string;
  securityVersion!: number;
}

/** The fields of {@link AccountKeysResponse}, which is all a body — parsed or built — holds. */
export type AccountKeysBody = Omit<AccountKeysResponse, "toAccountCryptographicState">;

export class AccountKeysResponse {
  object!: "privateKeys";
  publicKeyEncryptionKeyPair!: PublicKeyEncryptionKeyPairResponse;
  signatureKeyPair?: SignatureKeyPairResponse;
  securityState?: SecurityStateResponse;

  /**
   * These keys as an instance, from the fields alone.
   *
   * The fields are all a response body carries — over the wire, or built from an account — and the
   * class carries a conversion, so the two have to be joined up somewhere.
   */
  static fromAccountKeysResponse(body: AccountKeysBody): AccountKeysResponse {
    return Object.assign(new AccountKeysResponse(), body);
  }

  /** The account's wrapped private key, whichever generation it is. */
  static wrappedPrivateKeyOf(user: UserEntity): string {
    const state = user.accountCryptographicState;
    return "V1" in state ? state.V1.private_key : state.V2.private_key;
  }

  /**
   * This account's keys in the SDK's `WrappedAccountCryptographicState`.
   *
   * A V1 account carries only a key pair; a V2 account must also carry the signature key pair and
   * security state, which is what makes it V2.
   */
  toAccountCryptographicState(): WrappedAccountCryptographicState {
    const { publicKeyEncryptionKeyPair: pair, signatureKeyPair, securityState } = this;

    if (signatureKeyPair === undefined || securityState === undefined) {
      return { V1: { private_key: asEncString(pair.wrappedPrivateKey) } };
    }

    return {
      V2: {
        private_key: asEncString(pair.wrappedPrivateKey),
        signing_key: asEncString(signatureKeyPair.wrappedSigningKey),
        security_state: asSignedSecurityState(securityState.securityState),
        signed_public_key:
          pair.signedPublicKey === undefined ? undefined : asSignedPublicKey(pair.signedPublicKey),
      },
    };
  }

  /** The account's keys as the server serves them. */
  static fromUser(user: UserEntity): AccountKeysResponse {
    const state = user.accountCryptographicState;

    if ("V1" in state) {
      return AccountKeysResponse.fromAccountKeysResponse({
        object: "privateKeys",
        publicKeyEncryptionKeyPair: {
          object: "publicKeyEncryptionKeyPair",
          wrappedPrivateKey: state.V1.private_key,
          publicKey: user.publicKey,
        },
      });
    }

    if (user.verifyingKey === null) {
      throw new Error(`V2 account ${user.email} has no verifying key`);
    }

    return AccountKeysResponse.fromAccountKeysResponse({
      object: "privateKeys",
      publicKeyEncryptionKeyPair: {
        object: "publicKeyEncryptionKeyPair",
        wrappedPrivateKey: state.V2.private_key,
        publicKey: user.publicKey,
        ...(state.V2.signed_public_key === undefined
          ? {}
          : { signedPublicKey: state.V2.signed_public_key }),
      },
      signatureKeyPair: {
        object: "signatureKeyPair",
        wrappedSigningKey: state.V2.signing_key,
        verifyingKey: user.verifyingKey,
      },
      securityState: {
        securityState: state.V2.security_state,
        securityVersion: user.securityVersion,
      },
    });
  }
}

/**
 * Where each field of a stored cipher comes from when a write lands.
 *
 * `request` — the client owns it, and omitting it clears it.
 * `previous` — the client cannot change it, so an edit keeps what was there.
 * `server` — the server owns it outright; see {@link CipherRequest.toCipher}.
 */
export const CIPHER_FIELD_SOURCE = {
  type: "request",
  name: "request",
  notes: "request",
  key: "request",
  favorite: "request",
  reprompt: "request",
  folderId: "request",
  login: "request",
  card: "request",
  identity: "request",
  secureNote: "request",
  sshKey: "request",
  bankAccount: "request",
  driversLicense: "request",
  passport: "request",
  fields: "request",
  passwordHistory: "request",
  data: "request",
  archivedDate: "request",
  organizationId: "server",
  collectionIds: "server",
  attachments: "previous",
  permissions: "previous",
  organizationUseTotp: "previous",
  edit: "previous",
  viewPassword: "previous",
  localData: "previous",
  id: "server",
  creationDate: "server",
  revisionDate: "server",
  deletedDate: "server",
} as const satisfies Record<keyof Cipher, "request" | "previous" | "server">;

/** Fields the server, not the client, decides the value of. */
export interface CipherServerFields {
  id: string;
  /** The owning organization, or `null` for a user cipher. Assigned on create, kept on edit. */
  organizationId: string | null;
  /**
   * The collections the cipher is in.
   *
   * Not part of the cipher body: on a create it comes from the `POST /ciphers/create` wrapper
   * ({@link CipherCreateRequest}), and on an edit it is kept, since a collection move is its own
   * endpoint.
   */
  collectionIds: string[];
  creationDate: string;
  revisionDate: string;
  deletedDate: string | null;
}

/**
 * `CipherRequestModel` — the body of `POST /ciphers` and `PUT /ciphers/:id`.
 *
 * The encrypted sub-objects are structurally the domain model's, so they are typed off `Cipher`
 * rather than re-declared. Only the top level differs, and only the top level needs pinning.
 */
export class CipherRequest {
  type!: CipherType;
  /** Absent on a blob-encrypted cipher, whose name lives inside the sealed `data` blob. */
  name?: string | null;
  notes?: string | null;
  key?: string | null;
  favorite?: boolean;
  reprompt?: CipherRepromptType;
  organizationId?: string | null;
  folderId?: string | null;
  encryptedFor?: string | null;
  encryptedByKeyId?: string | null;
  login?: Login | undefined;
  card?: Card | undefined;
  identity?: Identity | undefined;
  secureNote?: SecureNote | undefined;
  sshKey?: SshKey | undefined;
  bankAccount?: BankAccount | undefined;
  driversLicense?: DriversLicense | undefined;
  passport?: Passport | undefined;
  fields?: Field[] | undefined;
  passwordHistory?: PasswordHistory[] | undefined;
  attachments2?: Record<string, { fileName: string; key: string }> | null;
  data?: string | undefined;
  archivedDate?: string | null;
  /** The revision the client believes it is editing. A regression means someone else wrote first. */
  lastKnownRevisionDate?: string | null;
  isOrganizationCipher?: boolean;

  /**
   * A posted cipher, merged over what was stored, as the database will hold it.
   *
   * `previous` is `undefined` for a create. Every key of {@link CIPHER_FIELD_SOURCE} is assigned
   * here, so adding a field to `Cipher` without deciding where it comes from fails to compile.
   */
  static toCipher(
    posted: CipherRequest,
    previous: Cipher | undefined,
    server: CipherServerFields,
  ): Cipher {
    return {
      id: asCipherId(server.id),
      creationDate: server.creationDate,
      revisionDate: server.revisionDate,
      deletedDate: server.deletedDate ?? undefined,

      type: posted.type,
      name: optionalEnc(posted.name),
      notes: optionalEnc(posted.notes),
      key: optionalEnc(posted.key),
      favorite: posted.favorite ?? false,
      reprompt: posted.reprompt ?? 0,
      folderId:
        posted.folderId === null || posted.folderId === undefined
          ? undefined
          : asFolderId(posted.folderId),
      login: posted.login,
      card: posted.card,
      identity: posted.identity,
      secureNote: posted.secureNote,
      sshKey: posted.sshKey,
      bankAccount: posted.bankAccount,
      driversLicense: posted.driversLicense,
      passport: posted.passport,
      fields: posted.fields,
      passwordHistory: posted.passwordHistory,
      data: posted.data,
      archivedDate: posted.archivedDate ?? undefined,

      organizationId:
        server.organizationId === null ? undefined : asOrganizationId(server.organizationId),
      collectionIds: server.collectionIds.map(asCollectionId),
      attachments: previous?.attachments,
      permissions: previous?.permissions,
      organizationUseTotp: previous?.organizationUseTotp ?? true,
      edit: previous?.edit ?? true,
      viewPassword: previous?.viewPassword ?? true,
      localData: previous?.localData,
    };
  }
}

/**
 * `CipherCreateRequestModel` — the body of `POST /ciphers/create`.
 *
 * The SDK posts here instead of `POST /ciphers` when the new item goes into collections, and the
 * cipher sits one level down with the collection ids beside it.
 */
export class CipherCreateRequest {
  cipher!: CipherRequest;
  collectionIds?: string[];
}

export class CipherResponse {
  object!: "cipherDetails";
  id!: string;
  organizationId!: string | null;
  folderId!: string | null;
  collectionIds!: string[];
  type!: CipherType;
  name!: string | null;
  notes!: string | null;
  login!: Login | undefined;
  card!: Card | undefined;
  identity!: Identity | undefined;
  secureNote!: SecureNote | undefined;
  sshKey!: SshKey | undefined;
  bankAccount!: BankAccount | undefined;
  driversLicense!: DriversLicense | undefined;
  passport!: Passport | undefined;
  fields!: Field[] | undefined;
  passwordHistory!: PasswordHistory[] | undefined;
  attachments!: Attachment[] | undefined;
  permissions!: CipherPermissions | undefined;
  data!: string | undefined;
  key!: string | null;
  favorite!: boolean;
  reprompt!: CipherRepromptType;
  organizationUseTotp!: boolean;
  edit!: boolean;
  viewPassword!: boolean;
  creationDate!: string;
  revisionDate!: string;
  deletedDate!: string | null;
  archivedDate!: string | null;

  /** A stored cipher as `GET /sync` and the cipher write endpoints return it. */
  static fromCipher(cipher: Cipher): CipherResponse {
    return {
      object: "cipherDetails",
      id: asString(cipher.id ?? ""),
      organizationId: optionalString(cipher.organizationId),
      folderId: optionalString(cipher.folderId),
      collectionIds: cipher.collectionIds.map(asString),
      type: cipher.type,
      name: cipher.name ?? null,
      notes: cipher.notes ?? null,
      login: cipher.login,
      card: cipher.card,
      identity: cipher.identity,
      secureNote: cipher.secureNote,
      sshKey: cipher.sshKey,
      bankAccount: cipher.bankAccount,
      driversLicense: cipher.driversLicense,
      passport: cipher.passport,
      fields: cipher.fields,
      passwordHistory: cipher.passwordHistory,
      attachments: cipher.attachments,
      permissions: cipher.permissions,
      data: cipher.data,
      key: cipher.key ?? null,
      favorite: cipher.favorite,
      reprompt: cipher.reprompt,
      organizationUseTotp: cipher.organizationUseTotp,
      edit: cipher.edit,
      viewPassword: cipher.viewPassword,
      creationDate: cipher.creationDate,
      revisionDate: cipher.revisionDate,
      deletedDate: cipher.deletedDate ?? null,
      archivedDate: cipher.archivedDate ?? null,
    };
  }
}

/** `FolderRequestModel` — the body of `POST /folders` and `PUT /folders/:id`. */
export class FolderRequest {
  name!: string;

  static toFolder(posted: FolderRequest, id: string, revisionDate: string): Folder {
    return { id: asFolderId(id), name: asEncString(posted.name), revisionDate };
  }
}

export class FolderResponse {
  object!: "folder";
  id!: string;
  name!: string;
  revisionDate!: string;

  static fromFolder(folder: Folder): FolderResponse {
    return {
      object: "folder",
      id: asString(folder.id ?? ""),
      name: folder.name,
      revisionDate: folder.revisionDate,
    };
  }
}

/**
 * `MasterPasswordUnlockResponseModel`.
 *
 * The wrapped key is `masterKeyEncryptedUserKey` here, not the request models'
 * `masterKeyWrappedUserKey`. The two spellings are not interchangeable.
 */
export class MasterPasswordUnlockResponse {
  kdf!: KdfModel;
  masterKeyEncryptedUserKey!: string;
  salt!: string;
  containedKeyId?: string;

  static fromStored(unlock: StoredMasterPasswordUnlock): MasterPasswordUnlockResponse {
    return {
      kdf: KdfModel.fromKdf(unlock.kdf),
      masterKeyEncryptedUserKey: unlock.masterKeyWrappedUserKey,
      salt: unlock.salt,
      ...(unlock.containedKeyId === undefined ? {} : { containedKeyId: unlock.containedKeyId }),
    };
  }
}

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
  masterPasswordUnlock?: MasterPasswordUnlockResponse;
  v2UpgradeToken?: V2UpgradeTokenResponse;
  userKeyId?: string;

  static fromUser(user: UserEntity): UserDecryptionResponse {
    return {
      ...(user.masterPasswordUnlock === null
        ? {}
        : {
            masterPasswordUnlock: MasterPasswordUnlockResponse.fromStored(
              user.masterPasswordUnlock,
            ),
          }),
      ...(user.upgradeToken === undefined
        ? {}
        : {
            v2UpgradeToken: {
              wrappedUserKey1: String(user.upgradeToken.wrapped_user_key_1),
              wrappedUserKey2: String(user.upgradeToken.wrapped_user_key_2),
            },
          }),
      ...(user.userKeyId === undefined ? {} : { userKeyId: user.userKeyId }),
    };
  }
}

/** The subset of `ProfileResponseModel` the SDK reads. */
export class ProfileResponse {
  object!: "profile";
  id!: string;
  email!: string;
  key!: string | null;
  privateKey!: string | null;
  securityStamp!: string | null;
  organizations!: [];
  /** The account's cryptographic state, which a rotation reads the current keys from. */
  accountKeys!: AccountKeysResponse;

  static fromUser(user: UserEntity): ProfileResponse {
    return {
      object: "profile",
      id: user.userId,
      email: user.email,
      key: user.masterPasswordUnlock?.masterKeyWrappedUserKey ?? null,
      privateKey: AccountKeysResponse.wrappedPrivateKeyOf(user),
      securityStamp: null,
      organizations: [],
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
  static forUser(user: UserEntity, vault: { ciphers: Cipher[]; folders: Folder[] }): SyncResponse {
    return {
      object: "sync",
      profile: ProfileResponse.fromUser(user),
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

/** What the server answers with when it refuses. */
export class ErrorResponse {
  message!: string;
  validationErrors?: Record<string, string[]>;
}
