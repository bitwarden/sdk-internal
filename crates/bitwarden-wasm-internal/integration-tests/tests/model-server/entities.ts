// The tables the model server keeps.
//
// Entities hold *encrypted* domain models — the same shapes the committed test vectors record and the
// same shapes `GET /sync` serves — so seeding is a copy rather than a conversion, and a dump is
// directly comparable to a vector.
//
// Revisions come from a monotonic counter rather than the clock. A real server stamps wall-clock time,
// but tests need dumps that are byte-stable across runs, so this advances a fixed base instant by one
// second per write. The behaviour that matters — revisions always move forward, and a stale write can
// be detected — is preserved.

import type { Cipher, Folder, Send } from "@bitwarden/sdk-internal";

/** The instant the first write is stamped with. Arbitrary, but fixed. */
const REVISION_EPOCH = Date.UTC(2025, 0, 1, 0, 0, 0);

export class RevisionClock {
  private tick = 0;

  /** The next revision, one second on from the last. */
  next(): string {
    this.tick += 1;
    return new Date(REVISION_EPOCH + this.tick * 1000).toISOString().replace(".000Z", "Z");
  }

  /** The current revision without advancing, for seeding. */
  current(): string {
    return new Date(REVISION_EPOCH + this.tick * 1000).toISOString().replace(".000Z", "Z");
  }
}

/**
 * Client-side material the server would never hold, kept alongside the account so the harness can
 * unlock it from an email alone.
 */
export interface TestCredentials {
  /** Each entry is directly usable as the `method` of an `InitUserCryptoRequest`. */
  unlockMethods: any[];
  password: string;
  upgradeToken?: any;
  /** Organization keys sealed to this account, keyed by organization id. */
  organizationKeys: Record<string, any>;
  /** The vector's slug, for error messages and cross-referencing. */
  vectorName: string;
  /**
   * Plaintext the client must never put on the wire.
   *
   * Held so the server can police it on every single request, which is what replaced the handful of
   * per-test "the posted body does not contain the password" assertions. An invariant that runs
   * everywhere beats a spot check that runs in four places.
   */
  neverSend: { label: string; value: string }[];
}

/** An account as the server holds it. */
export interface UserEntity {
  userId: string;
  email: string;
  /** `WrappedAccountCryptographicState`, in the SDK's shape. */
  accountCryptographicState: any;
  publicKey: string;
  verifyingKey: string | null;
  securityVersion: number;
  /**
   * The account's KDF settings, held separately from `masterPasswordUnlock` because an account with no
   * master password — key connector, TDE — still has them and still needs them to initialize.
   */
  kdf: any;
  /** Test-only; see {@link TestCredentials}. */
  credentials: TestCredentials;
  /** Master-password unlock data, or `null` for an account with no master password. */
  masterPasswordUnlock: {
    masterKeyWrappedUserKey: string;
    salt: string;
    /** The SDK-shaped `Kdf`; the sync serializer converts it to the server's numeric form. */
    kdf: any;
  } | null;
  /** Set once the account enrolls in key connector unlock. */
  keyConnectorKeyWrappedUserKey?: string;
  /**
   * The unlock method the account last declared, as the server's `UnlockMethod` numbers it:
   * 0 = TDE, 1 = master password, 2 = key connector. Recorded by a key rotation.
   */
  unlockMethod?: number;
  /** Recorded by a key rotation: the user key re-sealed to each trusted organization. */
  accountRecoveryUnlockData: { organizationId?: string; resetPasswordKey?: string }[];
  /** Recorded by a key rotation: the user key re-sealed to each trusted emergency-access grantee. */
  emergencyAccessUnlockData: { id?: string; keyEncrypted?: string }[];
  /** Device keys posted during TDE enrolment, keyed by device identifier. */
  devices: Map<string, { encryptedPrivateKey: string; encryptedUserKey: string }>;
}

/** An organization, its members and its vault. */
export interface OrganizationEntity {
  organizationId: string;
  name: string;
  publicKey: string;
  wrappedPrivateKey: string;
  organizationKeyId: string | null;
  /** Members keyed by user id, each holding the org key sealed to them. */
  members: Map<
    string,
    {
      userId: string;
      /** The user vector this member corresponds to, for cross-referencing in tests. */
      userVectorName: string;
      organizationKeySealedToMember: string;
      /** The member's user key sealed to the org public key, when enrolled in account recovery. */
      accountRecoveryKey?: string;
      resetPasswordEnrolled: boolean;
    }
  >;
}

/** An organization invite, as the invite-link flow deals in. */
export interface InviteEntity {
  id: string;
  organizationId: string;
  /** The opaque sealed invite blob. */
  invite: string;
  code: string;
  supportsConfirmation: boolean;
  allowedDomains: string[];
  creationDate: string;
}

/** Every table, plus the shared revision clock. */
export class Database {
  readonly revisions = new RevisionClock();
  readonly users = new Map<string, UserEntity>();
  readonly organizations = new Map<string, OrganizationEntity>();
  readonly invites = new Map<string, InviteEntity>();

  /** Vault items, keyed by item id. `ownerId` is the user each item belongs to. */
  readonly ciphers = new Map<string, { ownerId: string; cipher: Cipher }>();
  readonly folders = new Map<string, { ownerId: string; folder: Folder }>();
  readonly sends = new Map<string, { ownerId: string; send: Send }>();

  user(userId: string): UserEntity {
    const user = this.users.get(userId);
    if (user === undefined) {
      throw new Error(`no user ${userId} in the model server; seed it first`);
    }
    return user;
  }

  /** Looks an account up by email, which is how tests address them. */
  userByEmail(email: string): UserEntity {
    const found = [...this.users.values()].find((user) => user.email === email);
    if (found === undefined) {
      const known = [...this.users.values()].map((user) => user.email);
      throw new Error(
        `no account ${email} in the model server; seeded accounts are [${known.join(", ")}]`,
      );
    }
    return found;
  }

  /** Every cipher belonging to `ownerId`, in insertion order. */
  ciphersFor(ownerId: string): Cipher[] {
    return [...this.ciphers.values()]
      .filter((entry) => entry.ownerId === ownerId)
      .map((entry) => entry.cipher);
  }

  foldersFor(ownerId: string): Folder[] {
    return [...this.folders.values()]
      .filter((entry) => entry.ownerId === ownerId)
      .map((entry) => entry.folder);
  }

  sendsFor(ownerId: string): Send[] {
    return [...this.sends.values()]
      .filter((entry) => entry.ownerId === ownerId)
      .map((entry) => entry.send);
  }
}
