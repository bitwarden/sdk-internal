// The rows the model server keeps.
//
// Entities hold *encrypted* domain models — the same shapes the committed test vectors record and
// the same shapes `GET /sync` serves — so seeding an account is a copy rather than a conversion, and
// a dump is directly comparable to a vector.

import type {
  Cipher,
  EncString,
  Folder,
  InitUserCryptoMethod,
  Kdf,
  Send,
  V2UpgradeToken,
  WrappedAccountCryptographicState,
} from "@bitwarden/sdk-internal";

/** The instant the first write is stamped with. Arbitrary, but fixed. */
const REVISION_EPOCH = Date.UTC(2025, 0, 1, 0, 0, 0);

/** One second per write, so a dump is byte-stable across runs. */
const REVISION_STEP_MS = 1000;

/**
 * Stamps writes with a monotonic revision.
 *
 * A real server uses wall-clock time. Tests need dumps that compare equal across runs, so this
 * advances a fixed instant instead. The behaviour that matters — revisions only move forward, and a
 * stale write is detectable — is unchanged.
 */
export class RevisionClock {
  private tick = 0;

  /** The next revision, one second on from the last. */
  next(): string {
    this.tick += 1;
    return this.at(this.tick);
  }

  /** The current revision without advancing, for seeding. */
  current(): string {
    return this.at(this.tick);
  }

  private at(tick: number): string {
    return new Date(REVISION_EPOCH + tick * REVISION_STEP_MS).toISOString().replace(".000Z", "Z");
  }
}

/**
 * Client-side material a real server would never hold, kept beside the account so the harness can
 * bring it up from an email alone.
 */
export interface TestCredentials {
  /** Each entry is directly usable as the `method` of an `InitUserCryptoRequest`. */
  unlockMethods: InitUserCryptoMethod[];
  password: string;
  upgradeToken?: V2UpgradeToken;
  /** Organization keys sealed to this account, keyed by organization id. */
  organizationKeys: Record<string, string>;
  /** The vector's slug, for error messages and cross-referencing. */
  vectorName: string;
  /**
   * Plaintext this account must never put on the wire.
   *
   * The server checks every request body against every seeded account's entries, which is what
   * replaces the per-test "the posted body does not contain the password" spot checks. An invariant
   * that runs everywhere beats a check that runs in four places.
   */
  neverSend: { label: string; value: string }[];
}

/** Master-password unlock data as the server holds it. */
export interface StoredMasterPasswordUnlock {
  masterKeyWrappedUserKey: EncString;
  salt: string;
  /** The SDK's `Kdf`; the serializers convert it to the server's numeric form on the way out. */
  kdf: Kdf;
  containedKeyId?: string;
}

/** An account as the server holds it. */
export interface UserEntity {
  userId: string;
  email: string;
  accountCryptographicState: WrappedAccountCryptographicState;
  publicKey: string;
  verifyingKey: string | null;
  securityVersion: number;
  /**
   * The account's KDF settings, held separately from {@link masterPasswordUnlock} because an account
   * with none — key connector, trusted device — still has them and still needs them to initialize.
   */
  kdf: Kdf;
  /** `null` for an account with no master password. */
  masterPasswordUnlock: StoredMasterPasswordUnlock | null;
  /** Test-only; see {@link TestCredentials}. */
  credentials: TestCredentials;
}

/** A member of an organization, as the server holds it. */
export interface OrganizationMember {
  userId: string;
  /** The organization key sealed to this member's public key. */
  organizationKeySealedToMember: string;
  /** Present only for a member enrolled in account recovery. */
  accountRecoveryKey?: string;
}

/** An organization as the server holds it. */
export interface OrganizationEntity {
  organizationId: string;
  name: string;
  publicKey: string;
  wrappedPrivateKey: string;
  organizationKeyId: string | null;
  members: Map<string, OrganizationMember>;
}

/** A vault item together with the account or organization that owns it. */
export interface OwnedItem<T> {
  ownerId: string;
  item: T;
}

export type StoredCipher = OwnedItem<Cipher>;
export type StoredFolder = OwnedItem<Folder>;
export type StoredSend = OwnedItem<Send>;
