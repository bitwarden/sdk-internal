// Domain model <-> server DTO conversion, in one place.
//
// This replaces four hand-rolled builders that had each drifted apart: `toResponseModel`
// (cipher-crud), `folderResponse` (folder-crud), `accountKeys`/`kdfResponse` (rotation-server) and
// `cipherWith` (attachments).
//
// Two response shapes are deliberately inconsistent because the real API is: attachment *create*
// returns the cipher under `cipherResponse`, attachment *delete* wraps it as `{ cipher }`. Both are
// reproduced here rather than smoothed over — a test that passes against a tidier fake would not
// prove anything about the client.

import type { Folder } from "@bitwarden/sdk-internal";

import type { Database, OrganizationEntity, UserEntity } from "./entities";

const KDF_TYPE = { pbkdf2: 0, argon2id: 1 } as const;

/** SDK `Kdf` -> the numeric form the server's `MasterPasswordUnlock` model uses. */
export function kdfToResponse(kdf: any): Record<string, unknown> {
  if ("pBKDF2" in kdf) {
    return { kdfType: KDF_TYPE.pbkdf2, iterations: kdf.pBKDF2.iterations };
  }
  return {
    kdfType: KDF_TYPE.argon2id,
    iterations: kdf.argon2id.iterations,
    memory: kdf.argon2id.memory,
    parallelism: kdf.argon2id.parallelism,
  };
}

/** The server's numeric KDF form -> SDK `Kdf`. */
export function kdfFromResponse(kdf: any): unknown {
  if (kdf?.kdfType === KDF_TYPE.argon2id) {
    return {
      argon2id: {
        iterations: kdf.iterations,
        memory: kdf.memory,
        parallelism: kdf.parallelism,
      },
    };
  }
  return { pBKDF2: { iterations: kdf?.iterations ?? 600_000 } };
}

/**
 * The `accountKeys` half of a sync profile.
 *
 * The shape is keyed on the account's version: a V1 account must send no signature key pair and no
 * security state, and a V2 account must send both, or `WrappedAccountCryptographicState::try_from`
 * rejects the response as inconsistent.
 */
export function accountKeysResponse(user: UserEntity): Record<string, unknown> {
  const state = user.accountCryptographicState;

  if ("V1" in state) {
    return {
      publicKeyEncryptionKeyPair: {
        wrappedPrivateKey: state.V1.private_key,
        publicKey: user.publicKey,
        signedPublicKey: null,
      },
      signatureKeyPair: null,
      securityState: null,
    };
  }

  return {
    publicKeyEncryptionKeyPair: {
      wrappedPrivateKey: state.V2.private_key,
      publicKey: user.publicKey,
      signedPublicKey: state.V2.signed_public_key,
    },
    signatureKeyPair: {
      wrappedSigningKey: state.V2.signing_key,
      verifyingKey: user.verifyingKey,
    },
    securityState: {
      securityState: state.V2.security_state,
      securityVersion: user.securityVersion,
    },
  };
}

/** The wrapped private key, whichever version the account is in. */
export function wrappedPrivateKeyOf(user: UserEntity): string {
  const state = user.accountCryptographicState;
  return ("V1" in state ? state.V1.private_key : state.V2.private_key).toString();
}

/** `GET /sync`. */
export function syncResponse(db: Database, user: UserEntity): Record<string, unknown> {
  return {
    object: "sync",
    profile: {
      object: "profile",
      id: user.userId,
      email: user.email,
      accountKeys: accountKeysResponse(user),
      organizations: [...db.organizations.values()]
        .filter((organization) => organization.members.has(user.userId))
        .map((organization) => ({
          object: "profileOrganization",
          id: organization.organizationId,
          name: organization.name,
        })),
    },
    userDecryption: {
      masterPasswordUnlock:
        user.masterPasswordUnlock === null
          ? null
          : {
              kdf: kdfToResponse(user.masterPasswordUnlock.kdf),
              masterKeyWrappedUserKey: user.masterPasswordUnlock.masterKeyWrappedUserKey,
              salt: user.masterPasswordUnlock.salt,
            },
    },
    // Only the account's own items participate; organization ciphers are filtered out server-side.
    ciphers: db.ciphersFor(user.userId),
    folders: db.foldersFor(user.userId),
    sends: db.sendsFor(user.userId),
    collections: [],
    domains: null,
    policies: [],
  };
}

/** `GET /accounts/keys`, which only a V1 account reaches. */
export function accountsKeysResponse(user: UserEntity): Record<string, unknown> {
  return {
    object: "keys",
    publicKey: user.publicKey,
    privateKey: wrappedPrivateKeyOf(user),
  };
}

/** A stored `Cipher` -> `CipherDetailsResponseModel`. */
export function cipherToResponse(cipher: any): Record<string, unknown> {
  return {
    object: "cipherDetails",
    id: cipher.id,
    organizationId: cipher.organizationId ?? null,
    folderId: cipher.folderId ?? null,
    collectionIds: cipher.collectionIds ?? [],
    type: cipher.type,
    name: cipher.name,
    notes: cipher.notes ?? null,
    login: cipher.login ?? null,
    card: cipher.card ?? null,
    identity: cipher.identity ?? null,
    secureNote: cipher.secureNote ?? null,
    sshKey: cipher.sshKey ?? null,
    bankAccount: cipher.bankAccount ?? null,
    driversLicense: cipher.driversLicense ?? null,
    passport: cipher.passport ?? null,
    fields: cipher.fields ?? null,
    passwordHistory: cipher.passwordHistory ?? null,
    attachments: cipher.attachments ?? null,
    key: cipher.key ?? null,
    data: cipher.data ?? null,
    favorite: cipher.favorite ?? false,
    reprompt: cipher.reprompt ?? 0,
    organizationUseTotp: cipher.organizationUseTotp ?? false,
    edit: cipher.edit ?? true,
    viewPassword: cipher.viewPassword ?? true,
    creationDate: cipher.creationDate,
    revisionDate: cipher.revisionDate,
    deletedDate: cipher.deletedDate ?? null,
    archivedDate: cipher.archivedDate ?? null,
  };
}

/**
 * A posted `CipherRequestModel` -> a stored `Cipher`.
 *
 * Only the fields a write actually carries are taken from the request. Identity and metadata columns
 * it does not send — `creationDate`, `collectionIds`, permissions — are carried forward from the
 * stored cipher, which is what a real server does when it merges an update.
 *
 * The per-field legacy columns are taken from the request as-is rather than cleared: a blob-encrypted
 * write sends them absent and a legacy write sends them populated, so echoing the request is correct
 * for both and does not need to know which mode the client is in.
 */
export function requestToCipher(
  posted: any,
  previous: any | undefined,
  ids: { id: string; revisionDate: string },
): any {
  const attachments = attachmentsFromRequest(posted, previous);

  return {
    id: ids.id,
    organizationId: posted.organizationId ?? previous?.organizationId ?? null,
    folderId: posted.folderId ?? null,
    collectionIds: previous?.collectionIds ?? [],
    type: posted.type,
    name: posted.name,
    notes: posted.notes ?? null,
    login: posted.login ?? null,
    card: posted.card ?? null,
    identity: posted.identity ?? null,
    secureNote: posted.secureNote ?? null,
    sshKey: posted.sshKey ?? null,
    bankAccount: posted.bankAccount ?? null,
    driversLicense: posted.driversLicense ?? null,
    passport: posted.passport ?? null,
    fields: posted.fields ?? null,
    passwordHistory: posted.passwordHistory ?? null,
    attachments,
    key: posted.key ?? null,
    data: posted.data ?? null,
    favorite: posted.favorite ?? false,
    reprompt: posted.reprompt ?? 0,
    organizationUseTotp: previous?.organizationUseTotp ?? false,
    edit: previous?.edit ?? true,
    viewPassword: previous?.viewPassword ?? true,
    permissions: previous?.permissions ?? null,
    localData: null,
    creationDate: previous?.creationDate ?? "2024-01-08T00:00:00Z",
    revisionDate: ids.revisionDate,
    deletedDate: previous?.deletedDate ?? null,
    archivedDate: posted.archivedDate ?? null,
  };
}

/**
 * Rebuilds the attachment array from a write.
 *
 * A request carries `attachments2`, a map of `{ fileName, key }` keyed by attachment id, while the
 * stored model holds an array that also has `size`, `sizeName` and `url` — metadata the client never
 * re-sends, so it is merged back from what the server already had.
 */
function attachmentsFromRequest(posted: any, previous: any | undefined): any[] | null {
  const sent = posted.attachments2 ?? null;
  if (sent === null) {
    return previous?.attachments ?? null;
  }

  const known = new Map<string, any>(
    (previous?.attachments ?? []).map((attachment: any) => [attachment.id, attachment]),
  );
  const merged = Object.entries(sent).map(([id, value]: [string, any]) => ({
    ...known.get(id),
    id,
    fileName: value.fileName,
    key: value.key,
  }));
  return merged.length > 0 ? merged : null;
}

/** A stored `Folder` -> `FolderResponseModel`. */
export function folderToResponse(folder: any): Record<string, unknown> {
  return {
    object: "folder",
    id: folder.id,
    name: folder.name,
    revisionDate: folder.revisionDate,
  };
}

/** A posted folder -> a stored `Folder`. */
export function requestToFolder(posted: any, ids: { id: string; revisionDate: string }): Folder {
  return { id: ids.id, name: posted.name, revisionDate: ids.revisionDate } as unknown as Folder;
}

/** `GET /accounts/key-management/key-rotation-data`. */
export function keyRotationDataResponse(
  db: Database,
  user: UserEntity,
  emergencyAccess: { id: string; granteeVector: string; granteePublicKey: string }[],
): Record<string, unknown> {
  return {
    organizationPasswordResetKeyData: [...db.organizations.values()]
      .filter((organization) => organization.members.get(user.userId)?.accountRecoveryKey)
      .map((organization) => ({
        organizationId: organization.organizationId,
        organizationName: organization.name,
        organizationPublicKey: organization.publicKey,
      })),
    emergencyAccessKeyData: emergencyAccess.map((grant) => ({
      id: grant.id,
      granteeId: grant.id,
      granteeName: grant.granteeVector,
      granteeEmail: `${grant.granteeVector}@test.bitwarden.com`,
      publicKey: grant.granteePublicKey,
    })),
    trustedDeviceKeyData: [],
    passkeyKeyData: [],
  };
}

/** What an organization looks like to the invite-link endpoints. */
export function organizationKeysResponse(
  organization: OrganizationEntity,
): Record<string, unknown> {
  return {
    object: "organizationKeys",
    publicKey: organization.publicKey,
    privateKey: organization.wrappedPrivateKey,
  };
}
