// Reading the committed vectors in `/test-vectors`.
//
// The types here are declared rather than inferred from the JSON. A vector that drifts from the
// shape the harness expects then fails to compile at the use site, instead of loading as `any` and
// producing a decryption error twenty frames away.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type {
  Cipher,
  CipherView,
  Folder,
  FolderView,
  InitUserCryptoMethod,
  Kdf,
  Send,
  SendView,
  V2UpgradeToken,
  WrappedAccountCryptographicState,
} from "@bitwarden/sdk-internal";

import type { SeedAccount, SeedOrganization } from "../model-server/api-server";

/** Bumped whenever the recorded shape changes; every file must agree. */
export const SCHEMA_VERSION = 1;

const VECTORS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../../test-vectors");

/** The plaintext a vector records for its own key material, for asserting what a client derived. */
export interface RawCryptographicStateVector {
  userKey: string;
  userKeyId: string | null;
  masterKey: string | null;
  privateKey: string;
  publicKey: string;
  keyPairThumbprint: string;
  signingKey: string | null;
  verifyingKey: string | null;
  signingKeyId: string | null;
  signingKeyThumbprint: string | null;
  fingerprint: string;
}

/** Which generation of attachment key an attachment was recorded with. */
export type AttachmentVersion = "V0" | "V1" | "V2";

export interface CipherKeysVector {
  cipherKey: string | null;
  cipherKeyId: string | null;
  attachments: Record<
    string,
    { version: AttachmentVersion; key: string | null; keyId: string | null }
  >;
}

/** One vault item: the ciphertext the server serves, and the plaintext it must decrypt to. */
export interface VectorItem<Enc, Dec> {
  id: string;
  encrypted: Enc;
  decrypted: Dec;
}

export interface CipherVectorItem extends VectorItem<Cipher, CipherView> {
  /** True when the item is sealed as one blob rather than field by field. */
  blobEncrypted: boolean;
  keys: CipherKeysVector;
}

export interface VaultVector {
  ciphers: CipherVectorItem[];
  folders: VectorItem<Folder, FolderView>[];
  sends: VectorItem<Send, SendView>[];
  collections: unknown[];
}

export interface UserVector {
  schemaVersion: number;
  name: string;
  description: string;
  rngSeed: string;
  account: {
    userId: string;
    email: string;
    password: string;
    kdf: Kdf;
    securityVersion: number;
    accountCryptographicState: WrappedAccountCryptographicState;
    upgradeToken?: V2UpgradeToken;
    organizationKeys?: Record<string, string>;
  };
  unlockMethods: InitUserCryptoMethod[];
  rawCryptographicState: RawCryptographicStateVector;
  vault: VaultVector;
}

export interface OrganizationMemberVector {
  userVector: string;
  organizationKeySealedToMember: string;
  accountRecoveryKey?: string;
}

export interface OrganizationVector {
  schemaVersion: number;
  name: string;
  description: string;
  organizationId: string;
  organizationKey: string;
  organizationKeyId: string | null;
  publicKey: string;
  wrappedPrivateKey: string;
  members: OrganizationMemberVector[];
  vault: VaultVector;
}

export interface EmergencyAccessVector {
  schemaVersion: number;
  name: string;
  description: string;
  id: string;
  grantorVector: string;
  granteeVector: string;
  granteePublicKey: string;
  grantorUserKeySealedToGrantee: string;
}

function loadDir<T extends { schemaVersion: number; name: string }>(subdir: string): T[] {
  const directory = join(VECTORS_DIR, subdir);
  const files = readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .sort();

  if (files.length === 0) {
    throw new Error(`no vectors in ${directory}`);
  }

  return files.map((file) => {
    const vector = JSON.parse(readFileSync(join(directory, file), "utf8")) as T;
    if (vector.schemaVersion !== SCHEMA_VERSION) {
      throw new Error(
        `${subdir}/${file} is schema version ${vector.schemaVersion}, expected ${SCHEMA_VERSION}`,
      );
    }
    return vector;
  });
}

export const loadUserVectors = (): UserVector[] => loadDir<UserVector>("users");
export const loadOrganizationVectors = (): OrganizationVector[] =>
  loadDir<OrganizationVector>("organizations");
export const loadEmergencyAccessVectors = (): EmergencyAccessVector[] =>
  loadDir<EmergencyAccessVector>("emergency-access");

/** The named vector, or a listing of what is available. */
export function userVector(vectors: UserVector[], name: string): UserVector {
  const found = vectors.find((vector) => vector.name === name);
  if (found === undefined) {
    throw new Error(`no user vector ${name}; have ${vectors.map((v) => v.name).join(", ")}`);
  }
  return found;
}

/** The variant tag of an unlock method, for naming a test case. */
export function unlockMethodName(method: InitUserCryptoMethod): string {
  const [name] = Object.keys(method);
  if (name === undefined) {
    throw new Error("unlock method has no variant");
  }
  return name;
}

/** A user vector as the model server seeds it. */
export function toSeedAccount(vector: UserVector): SeedAccount {
  const raw = vector.rawCryptographicState;
  return {
    name: vector.name,
    account: {
      userId: vector.account.userId,
      email: vector.account.email,
      password: vector.account.password,
      kdf: vector.account.kdf,
      securityVersion: vector.account.securityVersion,
      accountCryptographicState: vector.account.accountCryptographicState,
      ...(vector.account.upgradeToken === undefined
        ? {}
        : { upgradeToken: vector.account.upgradeToken }),
      ...(vector.account.organizationKeys === undefined
        ? {}
        : { organizationKeys: vector.account.organizationKeys }),
    },
    unlockMethods: vector.unlockMethods,
    rawCryptographicState: {
      userKey: raw.userKey,
      masterKey: raw.masterKey,
      privateKey: raw.privateKey,
      publicKey: raw.publicKey,
      verifyingKey: raw.verifyingKey,
    },
    vault: {
      ciphers: vector.vault.ciphers,
      folders: vector.vault.folders,
    },
  };
}

/** An organization vector as the model server seeds it. */
export function toSeedOrganization(vector: OrganizationVector): SeedOrganization {
  return {
    organizationId: vector.organizationId,
    name: vector.name,
    publicKey: vector.publicKey,
    wrappedPrivateKey: vector.wrappedPrivateKey,
    organizationKeyId: vector.organizationKeyId,
    members: vector.members,
    vault: { ciphers: vector.vault.ciphers },
  };
}
