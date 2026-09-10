import type {
  Cipher,
  EncString,
  Folder,
  Kdf,
  KeyId,
  V2UpgradeToken,
  WrappedAccountCryptographicState,
} from "@bitwarden/sdk-internal";

/** Master-password unlock data as the server holds it. */
export interface StoredMasterPasswordUnlock {
  masterKeyWrappedUserKey: EncString;
  salt: string;
  /** The SDK's `Kdf`; the serializers convert it to the server's numeric form on the way out. */
  kdf: Kdf;
  containedKeyId?: string;
}

/** The keys a trusted device holds, as `PUT /devices/{identifier}/keys` posts them. */
export interface TrustedDeviceKeys {
  deviceProtectedUserKey: string;
  protectedDevicePublicKey: string;
  protectedDevicePrivateKey: string;
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
  /**
   * The id of the account's user key.
   *
   * Optional: an account created before key ids existed has none until it backfills one, which is
   * the state `user_key_id_needs_backfill` reports on.
   */
  userKeyId?: KeyId;
  /** `null` for an account with no master password. */
  masterPasswordUnlock: StoredMasterPasswordUnlock | null;
  /**
   * The master password authentication hash the identity service expects, or `null` for an account
   * with no master password.
   *
   * Recorded in the account's vector rather than derived here: the server never sees a password,
   * so it can only compare against what it was given.
   */
  masterPasswordAuthenticationHash: string | null;
  /**
   * The user key wrapped with the account's key-connector key.
   *
   * Set for an account that unlocks through key connector. The key itself lives on the
   * key-connector deployment, not here, so this alone unlocks nothing.
   */
  keyConnectorKeyWrappedUserKey?: EncString;
  /** Set while a V1 to V2 upgrade is outstanding; served in the account's decryption options. */
  upgradeToken?: V2UpgradeToken;
  /** Organization keys sealed to this account, keyed by organization id. */
  organizationKeys: Record<string, string>;
  /** The keys that make a device trusted, keyed by device identifier. */
  trustedDeviceKeys?: Record<string, TrustedDeviceKeys>;
}

/**
 * A cipher as the server holds it: the encrypted model plus who owns it.
 *
 * Exactly one owner is set. A user cipher lives in one account's vault; an organization cipher is
 * reachable by every member, so it cannot be attributed to the account that happened to create it.
 */
export interface CipherEntity {
  /** The account that owns it, or `null` for an organization cipher. */
  userId: string | null;
  /** The organization that owns it, or `null` for a user cipher. */
  organizationId: string | null;
  cipher: Cipher;
}

/** A folder as the server holds it. Folders are always personal — organizations have collections. */
export interface FolderEntity {
  userId: string;
  folder: Folder;
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
  members: OrganizationMember[];
}
