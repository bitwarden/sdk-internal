// The wire shapes, one interface per request and response body the model server handles.
//
// These mirror the serde representation of the generated models in `bitwarden-api-api` — the field
// names are the `#[serde(rename = ...)]` values, and a field the Rust model marks
// `skip_serializing_if = "Option::is_none"` is optional here.
//
// Declaring them is what makes the serializers checkable. A model server whose handlers take `any`
// can drop a field on the way out and still pass every test, which is the exact class of bug the
// integration suite exists to catch.

import type { Cipher, Folder } from "@bitwarden/sdk-internal";

/** The server's numeric `KdfType`. */
export const KdfType = { pbkdf2Sha256: 0, argon2id: 1 } as const;
export type KdfTypeValue = (typeof KdfType)[keyof typeof KdfType];

/** `KdfRequestModel`. `memory` and `parallelism` are absent for PBKDF2. */
export interface KdfModel {
  kdfType: KdfTypeValue;
  iterations: number;
  memory?: number;
  parallelism?: number;
}

/** `MasterPasswordAuthenticationDataRequestModel`. */
export interface MasterPasswordAuthenticationDataModel {
  kdf: KdfModel;
  masterPasswordAuthenticationHash: string;
  salt: string;
}

/** `MasterPasswordUnlockDataRequestModel`. */
export interface MasterPasswordUnlockDataModel {
  kdf: KdfModel;
  masterKeyWrappedUserKey: string;
  salt: string;
  containedKeyId?: string;
}

/** `ChangeKdfRequestModel` — the body of `POST /accounts/kdf`. */
export interface ChangeKdfRequest {
  /** Proof of possession, hashed under the *old* KDF. */
  masterPasswordHash: string;
  authenticationData: MasterPasswordAuthenticationDataModel;
  unlockData: MasterPasswordUnlockDataModel;
}

/** `PublicKeyEncryptionKeyPairResponseModel`. */
export interface PublicKeyEncryptionKeyPairResponse {
  object: "publicKeyEncryptionKeyPair";
  wrappedPrivateKey: string;
  publicKey: string;
  signedPublicKey?: string;
}

/** `SignatureKeyPairResponseModel`. */
export interface SignatureKeyPairResponse {
  object: "signatureKeyPair";
  wrappedSigningKey: string;
  verifyingKey: string;
}

/** `SecurityStateModel`. */
export interface SecurityStateResponse {
  securityState: string;
  securityVersion: number;
}

/**
 * `PrivateKeysResponseModel` — the body of `GET /accounts/keys`.
 *
 * A V1 account must omit `signatureKeyPair` and `securityState`; a V2 account must supply both.
 * `WrappedAccountCryptographicState::try_from` rejects any other combination as inconsistent, so
 * the two are not independently optional in practice.
 */
export interface AccountKeysResponse {
  object: "privateKeys";
  publicKeyEncryptionKeyPair: PublicKeyEncryptionKeyPairResponse;
  signatureKeyPair?: SignatureKeyPairResponse;
  securityState?: SecurityStateResponse;
}

/**
 * `CipherRequestModel` — the body of `POST /ciphers` and `PUT /ciphers/:id`.
 *
 * The encrypted sub-objects are structurally the domain model's, so they are typed off `Cipher`
 * rather than re-declared. Only the top level differs, and only the top level needs pinning.
 */
export interface CipherRequest {
  type: Cipher["type"];
  /** Absent on a blob-encrypted cipher, whose name lives inside the sealed `data` blob. */
  name?: string | null;
  notes?: string | null;
  key?: string | null;
  favorite?: boolean;
  reprompt?: Cipher["reprompt"];
  organizationId?: string | null;
  folderId?: string | null;
  encryptedFor?: string | null;
  encryptedByKeyId?: string | null;
  login?: Cipher["login"];
  card?: Cipher["card"];
  identity?: Cipher["identity"];
  secureNote?: Cipher["secureNote"];
  sshKey?: Cipher["sshKey"];
  bankAccount?: Cipher["bankAccount"];
  driversLicense?: Cipher["driversLicense"];
  passport?: Cipher["passport"];
  fields?: Cipher["fields"];
  passwordHistory?: Cipher["passwordHistory"];
  attachments2?: Record<string, { fileName: string; key: string }> | null;
  data?: Cipher["data"];
  archivedDate?: string | null;
  /** The revision the client believes it is editing. A regression means someone else wrote first. */
  lastKnownRevisionDate?: string | null;
  isOrganizationCipher?: boolean;
}

/** `CipherDetailsResponseModel`. */
export interface CipherResponse {
  object: "cipherDetails";
  id: string;
  organizationId: string | null;
  folderId: string | null;
  collectionIds: string[];
  type: Cipher["type"];
  name: string | null;
  notes: string | null;
  login: Cipher["login"];
  card: Cipher["card"];
  identity: Cipher["identity"];
  secureNote: Cipher["secureNote"];
  sshKey: Cipher["sshKey"];
  bankAccount: Cipher["bankAccount"];
  driversLicense: Cipher["driversLicense"];
  passport: Cipher["passport"];
  fields: Cipher["fields"];
  passwordHistory: Cipher["passwordHistory"];
  attachments: Cipher["attachments"];
  permissions: Cipher["permissions"];
  data: Cipher["data"];
  key: string | null;
  favorite: boolean;
  reprompt: Cipher["reprompt"];
  organizationUseTotp: boolean;
  edit: boolean;
  viewPassword: boolean;
  creationDate: string;
  revisionDate: string;
  deletedDate: string | null;
  archivedDate: string | null;
}

/** `FolderRequestModel` — the body of `POST /folders` and `PUT /folders/:id`. */
export interface FolderRequest {
  name: string;
}

/** `FolderResponseModel`. */
export interface FolderResponse {
  object: "folder";
  id: string;
  name: string;
  revisionDate: string;
}

/** The subset of `ProfileResponseModel` the SDK reads. */
export interface ProfileResponse {
  object: "profile";
  id: string;
  email: string;
  key: string | null;
  privateKey: string | null;
  securityStamp: string | null;
  organizations: [];
}

/** `SyncResponseModel`. */
export interface SyncResponse {
  object: "sync";
  profile: ProfileResponse;
  folders: FolderResponse[];
  collections: [];
  ciphers: CipherResponse[];
  domains: null;
  policies: [];
  sends: [];
}

/** What the server answers with when it refuses. */
export interface ErrorResponse {
  message: string;
  validationErrors?: Record<string, string[]>;
}

/** Convenience for the domain models the server stores, which is what the vectors record. */
export type StoredCipher = Cipher;
export type StoredFolder = Folder;
