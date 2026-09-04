// Conversions between the wire DTOs in `dto.ts` and the encrypted domain models the database holds.
//
// Cipher conversion is driven by one field table rather than two hand-written object literals, so a
// field cannot be read on the way in and forgotten on the way out.

import type { Cipher, Folder, Kdf } from "@bitwarden/sdk-internal";

import { asCipherId, asEncString, asFolderId, asString } from "../type-assertion-helpers";

import type { Database } from "./database";
import {
  KdfType,
  type AccountKeysResponse,
  type CipherRequest,
  type CipherResponse,
  type FolderRequest,
  type FolderResponse,
  type KdfModel,
  type MasterPasswordUnlockDataModel,
  type ProfileResponse,
  type SyncResponse,
} from "./dto";
import type { StoredMasterPasswordUnlock, UserEntity } from "./entities";

/** The SDK's `Kdf` in the server's numeric form. */
export function kdfToResponse(kdf: Kdf): KdfModel {
  if ("pBKDF2" in kdf) {
    return { kdfType: KdfType.pbkdf2Sha256, iterations: kdf.pBKDF2.iterations };
  }
  return {
    kdfType: KdfType.argon2id,
    iterations: kdf.argon2id.iterations,
    memory: kdf.argon2id.memory,
    parallelism: kdf.argon2id.parallelism,
  };
}

/**
 * The server's numeric KDF back into the SDK's `Kdf`.
 *
 * Throws on anything unrecognised. Defaulting here would let a malformed KDF through as a plausible
 * one, and the account would then be stored with settings nobody sent.
 */
export function kdfFromResponse(kdf: KdfModel): Kdf {
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

/** Master-password unlock data off the wire, as the server stores it. */
export function unlockDataFromRequest(
  posted: MasterPasswordUnlockDataModel,
): StoredMasterPasswordUnlock {
  return {
    masterKeyWrappedUserKey: asEncString(posted.masterKeyWrappedUserKey),
    salt: posted.salt,
    kdf: kdfFromResponse(posted.kdf),
    ...(posted.containedKeyId === undefined ? {} : { containedKeyId: posted.containedKeyId }),
  };
}

/** The account's wrapped private key, whichever generation it is. */
export function wrappedPrivateKeyOf(user: UserEntity): string {
  const state = user.accountCryptographicState;
  return "V1" in state ? state.V1.private_key : state.V2.private_key;
}

/**
 * `GET /accounts/keys`.
 *
 * A V1 account must omit the signature key pair and security state; a V2 account must carry both, or
 * `WrappedAccountCryptographicState::try_from` rejects the response as inconsistent.
 */
export function accountKeysResponse(user: UserEntity): AccountKeysResponse {
  const state = user.accountCryptographicState;

  if ("V1" in state) {
    return {
      object: "privateKeys",
      publicKeyEncryptionKeyPair: {
        object: "publicKeyEncryptionKeyPair",
        wrappedPrivateKey: state.V1.private_key,
        publicKey: user.publicKey,
      },
    };
  }

  if (user.verifyingKey === null) {
    throw new Error(`V2 account ${user.email} has no verifying key`);
  }

  return {
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
  };
}

function profileResponse(user: UserEntity): ProfileResponse {
  return {
    object: "profile",
    id: user.userId,
    email: user.email,
    key: user.masterPasswordUnlock?.masterKeyWrappedUserKey ?? null,
    privateKey: wrappedPrivateKeyOf(user),
    securityStamp: null,
    organizations: [],
  };
}

/** `GET /sync` for one account. */
export function syncResponse(db: Database, user: UserEntity): SyncResponse {
  return {
    object: "sync",
    profile: profileResponse(user),
    folders: db.folders.for(user.userId).map(folderToResponse),
    collections: [],
    ciphers: db.ciphers.for(user.userId).map(cipherToResponse),
    domains: null,
    policies: [],
    sends: [],
  };
}

/**
 * Where each field of a stored cipher comes from when a write lands.
 *
 * `request` — the client owns it, and omitting it clears it.
 * `previous` — the client cannot change it, so an edit keeps what was there.
 * `server` — the server owns it outright; see {@link requestToCipher}.
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
  organizationId: "previous",
  collectionIds: "previous",
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
  creationDate: string;
  revisionDate: string;
  deletedDate: string | null;
}

/**
 * A posted cipher, merged over what was stored, as the database will hold it.
 *
 * `previous` is `undefined` for a create. Every key of {@link CIPHER_FIELD_SOURCE} is assigned here,
 * so adding a field to `Cipher` without deciding where it comes from fails to compile.
 */
export function requestToCipher(
  posted: CipherRequest,
  previous: Cipher | undefined,
  server: CipherServerFields,
): Cipher {
  const optionalEnc = (value: string | null | undefined) =>
    value === null || value === undefined ? undefined : asEncString(value);

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

    organizationId: previous?.organizationId,
    collectionIds: previous?.collectionIds ?? [],
    attachments: previous?.attachments,
    permissions: previous?.permissions,
    organizationUseTotp: previous?.organizationUseTotp ?? true,
    edit: previous?.edit ?? true,
    viewPassword: previous?.viewPassword ?? true,
    localData: previous?.localData,
  };
}

/** A brand or absence, as the wire's nullable string. */
function optionalString(value: { toString(): string } | undefined): string | null {
  return value === undefined ? null : String(value);
}

/** A stored cipher as `GET /sync` and the cipher write endpoints return it. */
export function cipherToResponse(cipher: Cipher): CipherResponse {
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

export function requestToFolder(posted: FolderRequest, id: string, revisionDate: string): Folder {
  return { id: asFolderId(id), name: asEncString(posted.name), revisionDate };
}

export function folderToResponse(folder: Folder): FolderResponse {
  return {
    object: "folder",
    id: asString(folder.id ?? ""),
    name: folder.name,
    revisionDate: folder.revisionDate,
  };
}
