// Reading the committed vectors in `/test-vectors`.
//
// A vector is an account's definition: the ciphertext a server would serve, and the plaintext it
// must decrypt to. The types here are declared rather than inferred from the JSON, so a vector that
// drifts from the shape the harness expects fails to compile at the use site instead of loading as
// `any` and producing a decryption error twenty frames away.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type {
  Cipher,
  CipherView,
  Collection,
  CollectionView,
  Folder,
  FolderView,
  InitUserCryptoMethod,
  Kdf,
  Send,
  SendView,
  V2UpgradeToken,
  WrappedAccountCryptographicState,
} from "@bitwarden/sdk-internal";

import type { SeedAccount, SeedOrganization } from "../server-emulator/server-emulator";
import { asKeyId } from "../tests/type-assertion-helpers";

const VECTORS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../test-vectors");

/** The server's default, for a vector that records no KDF. */
const DEFAULT_KDF: Kdf = { pBKDF2: { iterations: 600_000 } };

/** The plaintext a vector records for its own key material, for asserting what a client derived. */
export interface RawCryptographicStateVector {
  userKey: string;
  userKeyId: string | null;
  /** RFC 9679 thumbprint of the user key, lowercase hex. */
  userKeyThumbprint: string;
  privateKey: string;
  publicKey: string;
  signingKey: string | null;
  verifyingKey: string | null;
  signingKeyId: string | null;
  /** RFC 9679 thumbprint of the user's signature keypair, lowercase hex. */
  signingKeyThumbprint: string | null;
  fingerprint: string;
}

/**
 * Which generation of attachment key an attachment was recorded with.
 *
 * - `V0`: no attachment key, on a cipher with no cipher key; contents sealed under the user/org key.
 * - `V1`: an attachment key of its own, wrapped by the user/org key, on a cipher with no cipher key.
 * - `V2`: an attachment key of its own, wrapped by the cipher key.
 */
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
  folders?: VectorItem<Folder, FolderView>[];
  sends: VectorItem<Send, SendView>[];
  collections?: VectorItem<Collection, CollectionView>[];
}

export interface UserVector {
  name: string;
  description: string;
  account: {
    userId: string;
    email: string;
    password?: string;
    kdf?: Kdf;
    securityVersion?: number;
    accountCryptographicState: WrappedAccountCryptographicState;
    upgradeToken?: V2UpgradeToken;
    organizationKeys?: Record<string, string>;
  };
  unlockMethods: InitUserCryptoMethod[];
  rawCryptographicState: RawCryptographicStateVector;
  vault: VaultVector;
}

/** A user vector whose account has a master password. */
export type MasterPasswordUserVector = UserVector & { account: { password: string } };

export interface OrganizationMemberVector {
  /** Name of the user vector this member is. */
  userVectorName: string;
  organizationKeySealedToMember: string;
  accountRecoveryKey?: string;
}

export interface OrganizationVector {
  name: string;
  description: string;
  organizationId: string;
  organizationKey: string;
  organizationKeyId: string | null;
  publicKey?: string;
  wrappedPrivateKey?: string;
  members: OrganizationMemberVector[];
  vault: VaultVector;
}

export interface EmergencyAccessVector {
  name: string;
  description: string;
  id: string;
  grantorVector: string;
  granteeVector: string;
  granteePublicKey: string;
  grantorUserKeySealedToGrantee: string;
}

function loadDir<T extends { name: string }>(subdir: string): T[] {
  const directory = join(VECTORS_DIR, subdir);
  const files = readdirSync(directory)
    .filter((name) => name.endsWith(".json"))
    .sort();

  if (files.length === 0) {
    throw new Error(`no vectors in ${directory}`);
  }

  return files.map((file) => JSON.parse(readFileSync(join(directory, file), "utf8")) as T);
}

export const loadUserVectors = (): UserVector[] => loadDir<UserVector>("users");
export const loadOrganizationVectors = (): OrganizationVector[] =>
  loadDir<OrganizationVector>("organizations");
export const loadEmergencyAccessVectors = (): EmergencyAccessVector[] =>
  loadDir<EmergencyAccessVector>("emergency-access");

/** The named vector, or a listing of what is available. */
function userVector(vectors: UserVector[], name: string): UserVector {
  const found = vectors.find((vector) => vector.name === name);
  if (found === undefined) {
    throw new Error(`no user vector ${name}; have ${vectors.map((v) => v.name).join(", ")}`);
  }
  return found;
}

/** Whether the vector's account has a master password. */
export const hasMasterPassword = (vector: UserVector): vector is MasterPasswordUserVector =>
  vector.account.password !== undefined;

/** The variant tag of an unlock method, for naming a test case. */
export function unlockMethodName(method: InitUserCryptoMethod): string {
  const [name] = Object.keys(method);
  if (name === undefined) {
    throw new Error("unlock method has no variant");
  }
  return name;
}

/** A user vector as the server emulator seeds it. */
export function toSeedAccount(vector: UserVector): SeedAccount {
  const raw = vector.rawCryptographicState;

  return {
    name: vector.name,
    account: {
      userId: vector.account.userId,
      email: vector.account.email,
      kdf: vector.account.kdf ?? DEFAULT_KDF,
      securityVersion: vector.account.securityVersion,
      // A V2 account's user key carries a key id from the start, so the server has always had one.
      ...(raw.userKeyId === null ? {} : { userKeyId: asKeyId(raw.userKeyId) }),
      accountCryptographicState: vector.account.accountCryptographicState,
      upgradeToken: vector.account.upgradeToken ?? undefined,
      organizationKeys: vector.account.organizationKeys ?? undefined,
    },
    unlockMethods: vector.unlockMethods,
    rawCryptographicState: {
      userKey: raw.userKey,
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

/**
 * An organization vector as the server emulator seeds it.
 *
 * Members are recorded by user-vector name; the emulator resolves them by email, so the referenced
 * vectors are looked up here.
 */
export function toSeedOrganization(
  vector: OrganizationVector,
  users: UserVector[] = loadUserVectors(),
): SeedOrganization {
  return {
    organizationId: vector.organizationId,
    name: vector.name,
    publicKey: vector.publicKey,
    wrappedPrivateKey: vector.wrappedPrivateKey,
    organizationKeyId: vector.organizationKeyId,
    members: vector.members.map((member) => ({
      userEmail: userVector(users, member.userVectorName).account.email,
      organizationKeySealedToMember: member.organizationKeySealedToMember,
      accountRecoveryKey: member.accountRecoveryKey ?? undefined,
    })),
    vault: { ciphers: vector.vault.ciphers },
  };
}
