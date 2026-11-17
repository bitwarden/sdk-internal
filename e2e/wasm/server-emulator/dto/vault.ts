// Ciphers and folders, as the server takes and serves them.

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
  Login,
  Passport,
  PasswordHistory,
  SecureNote,
  SshKey,
} from "@bitwarden/sdk-internal";

import {
  asCipherId,
  asCollectionId,
  asEncString,
  asFolderId,
  asOrganizationId,
  asString,
} from "../../tests/type-assertion-helpers";
import { optionalEnc, optionalString } from "./common";

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
  partialData: "server",
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

  /**
   * A served cipher as a client holds it: the inverse of {@link CipherResponse.fromCipher}.
   *
   * `localData` is the one field of `Cipher` with no wire representation — it is a client's own
   * record of when it last used the item, so a sync neither carries it nor clears it.
   */
  static toCipher(response: CipherResponse, previous?: Cipher): Cipher {
    return {
      id: asCipherId(response.id),
      organizationId:
        response.organizationId === null ? undefined : asOrganizationId(response.organizationId),
      folderId: response.folderId === null ? undefined : asFolderId(response.folderId),
      collectionIds: response.collectionIds.map(asCollectionId),
      type: response.type,
      name: optionalEnc(response.name),
      notes: optionalEnc(response.notes),
      login: response.login,
      card: response.card,
      identity: response.identity,
      secureNote: response.secureNote,
      sshKey: response.sshKey,
      bankAccount: response.bankAccount,
      driversLicense: response.driversLicense,
      passport: response.passport,
      fields: response.fields,
      passwordHistory: response.passwordHistory,
      attachments: response.attachments,
      permissions: response.permissions,
      data: response.data,
      key: optionalEnc(response.key),
      favorite: response.favorite,
      reprompt: response.reprompt,
      organizationUseTotp: response.organizationUseTotp,
      edit: response.edit,
      viewPassword: response.viewPassword,
      creationDate: response.creationDate,
      revisionDate: response.revisionDate,
      deletedDate: response.deletedDate ?? undefined,
      archivedDate: response.archivedDate ?? undefined,

      localData: previous?.localData,
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

  /** A served folder as a client holds it: the inverse of {@link FolderResponse.fromFolder}. */
  static toFolder(response: FolderResponse): Folder {
    return {
      id: asFolderId(response.id),
      name: asEncString(response.name),
      revisionDate: response.revisionDate,
    };
  }
}
