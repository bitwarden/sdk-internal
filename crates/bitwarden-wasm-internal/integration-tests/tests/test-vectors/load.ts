// Loads the committed test vectors from `/test-vectors` at the repository root.
//
// These are the same files the Rust loader reads. Both languages reading one set of files is the
// point: an encrypted account that decrypts in Rust but not in TypeScript is exactly the kind of FFI
// break this suite exists to catch.
//
// The types below mirror `bitwarden_test_vector`. They are declared, not inferred, so a schema
// change that the generator makes and this file does not follow shows up as a type error rather than
// as `undefined` at runtime.

import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import type {
  Cipher,
  CipherView,
  Collection,
  CollectionView,
  EncString,
  Folder,
  FolderView,
  InitUserCryptoMethod,
  Kdf,
  OrganizationId,
  Send,
  SendView,
  UnsignedSharedKey,
  UserId,
  V2UpgradeToken,
  WrappedAccountCryptographicState,
} from "@bitwarden/sdk-internal";

/** The schema version this file understands. Must match `bitwarden_test_vector::SCHEMA_VERSION`. */
export const SCHEMA_VERSION = 1;

export interface AccountVector {
  userId: UserId;
  email: string;
  password: string;
  kdf: Kdf;
  /** `1` for a V1 account, `2` or higher for a V2 account. */
  securityVersion: number;
  accountCryptographicState: WrappedAccountCryptographicState;
  /** Present only for an account mid-way through the V1 to V2 upgrade. */
  upgradeToken?: V2UpgradeToken;
  /** Organization keys, each sealed to this account's public key. Keyed by organization id. */
  organizationKeys?: Record<string, UnsignedSharedKey>;
}

/**
 * The key material an account should yield once unlocked.
 *
 * The three key types carry different notions of identity, so each is recorded as it actually exists:
 * symmetric keys and the signing key have a COSE `kid`, while RSA keys have none and are identified by
 * their RFC 9679 thumbprint.
 */
export interface RawCryptographicStateVector {
  userKey: string;
  /** Hex COSE `kid`. `null` on V1, whose `Aes256CbcHmac` keys carry none. */
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

/** Which of the three historical attachment layouts an attachment uses. */
export type AttachmentVersion = "V0" | "V1" | "V2";

export interface AttachmentKeysVector {
  version: AttachmentVersion;
  key: string | null;
  keyId: string | null;
}

export interface CipherKeysVector {
  cipherKey: string | null;
  cipherKeyId: string | null;
  attachments: Record<string, AttachmentKeysVector>;
}

export interface CipherVectorItem {
  id: string;
  /** Whether the cipher's data is sealed as a blob rather than field-encrypted. */
  blobEncrypted: boolean;
  encrypted: Cipher;
  decrypted: CipherView;
  keys: CipherKeysVector;
}

export interface VectorItem<Enc, Dec> {
  id: string;
  encrypted: Enc;
  decrypted: Dec;
}

export interface VaultVector {
  ciphers: CipherVectorItem[];
  folders: VectorItem<Folder, FolderView>[];
  sends: VectorItem<Send, SendView>[];
  /** Only ever populated on an organization vector: collections are keyed to the org. */
  collections: VectorItem<Collection, CollectionView>[];
}

export interface UserVector {
  schemaVersion: number;
  name: string;
  description: string;
  rngSeed: string;
  account: AccountVector;
  /** Each entry is directly usable as the `method` of an `InitUserCryptoRequest`. */
  unlockMethods: InitUserCryptoMethod[];
  rawCryptographicState: RawCryptographicStateVector;
  vault: VaultVector;
}

export interface OrganizationMemberVector {
  userVector: string;
  organizationKeySealedToMember: UnsignedSharedKey;
  /** The member's user key sealed to the organization's public key, if enrolled. */
  accountRecoveryKey?: UnsignedSharedKey;
}

export interface OrganizationVector {
  schemaVersion: number;
  name: string;
  description: string;
  organizationId: OrganizationId;
  organizationKey: string;
  organizationKeyId: string | null;
  /** SPKI DER, base64. What `GET /organizations/{id}/public-key` returns. */
  publicKey: string;
  wrappedPrivateKey: EncString;
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
  grantorUserKeySealedToGrantee: UnsignedSharedKey;
}

// `tests/test-vectors/` -> up five to the repository root.
const VECTORS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../../test-vectors");

function loadDir<T extends { schemaVersion: number; name: string }>(subdir: string): T[] {
  const dir = join(VECTORS_DIR, subdir);
  const vectors = readdirSync(dir)
    .filter((file) => file.endsWith(".json"))
    .sort()
    .map((file) => JSON.parse(readFileSync(join(dir, file), "utf8")) as T);

  if (vectors.length === 0) {
    throw new Error(`No test vectors found in ${dir}.`);
  }

  for (const vector of vectors) {
    if (vector.schemaVersion !== SCHEMA_VERSION) {
      throw new Error(
        `Test vector ${vector.name} declares schema version ${vector.schemaVersion}, expected ${SCHEMA_VERSION}. ` +
          `Update tests/test-vectors/load.ts to match the generator.`,
      );
    }
  }

  return vectors;
}

export function loadUserVectors(): UserVector[] {
  return loadDir<UserVector>("users");
}

export function loadOrganizationVectors(): OrganizationVector[] {
  return loadDir<OrganizationVector>("organizations");
}

export function loadEmergencyAccessVectors(): EmergencyAccessVector[] {
  return loadDir<EmergencyAccessVector>("emergency-access");
}

/** Finds a user vector by slug, failing loudly rather than returning `undefined`. */
export function userVector(vectors: UserVector[], name: string): UserVector {
  const found = vectors.find((vector) => vector.name === name);
  if (found === undefined) {
    throw new Error(`No user vector named ${name}`);
  }
  return found;
}

/** The variant name of an unlock method, for test titles. */
export function unlockMethodName(method: InitUserCryptoMethod): string {
  return Object.keys(method)[0];
}
