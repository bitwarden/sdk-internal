// The emulated backend as one object: the stored rows, the API model over them, and the `fetch`
// hook that connects the emulator to the SDK's HTTP client.

import { ApiServer } from "./api-server";
import { Database } from "./database";
import { EmergencyAccessServer } from "./emergency-access-server";
import type { EmergencyAccessStatusValue, EmergencyAccessTypeValue } from "./dto";
import type {
  AccountId,
  OrganizationMember,
  StoredMasterPasswordUnlock,
  UserEntity,
} from "./entities";
import { installHttpMock, type HttpMock, type Routes } from "./http-mock";
import { IdentityServer } from "./identity-server";
import { KeyConnectorServer } from "./key-connector-server";
import { API_URL, IDENTITY_URL, KEY_CONNECTOR_URL } from "./urls";

import { asAccountId, asEncString, fromUuid } from "../tests/type-assertion-helpers";
import {
  toSeedAccount,
  type EmergencyAccessVector,
  type PrivateKey,
  type UserVector,
  type VerifyingKey,
} from "../vectors/load";
import { testVectors } from "../vectors/test-vectors";

import type {
  Cipher,
  CipherView,
  Folder,
  FolderView,
  InitUserCryptoMethod,
  Kdf,
  KeyId,
  OrganizationId,
  PublicKey,
  SymmetricKey,
  UserId,
  V2UpgradeToken,
  WrappedAccountCryptographicState,
} from "@bitwarden/sdk-internal";

/** Binds every route key in `routes` to `origin`. */
function bindToOrigin(routes: Routes, origin: string): Routes {
  return Object.fromEntries(
    Object.entries(routes).map(([key, handler]) => {
      const separator = key.indexOf(" ");
      return [`${key.slice(0, separator)} ${origin}${key.slice(separator + 1)}`, handler];
    }),
  );
}

/** An account to seed, in the shape the committed test vectors record. */
export interface SeedAccount {
  /** The vector's slug, for error messages. */
  name: string;
  account: {
    userId: UserId;
    email: string;
    kdf: Kdf;
    userKeyId?: KeyId;
    securityVersion?: number;
    accountCryptographicState: WrappedAccountCryptographicState;
    upgradeToken?: V2UpgradeToken;
    organizationKeys?: Record<string, string>;
  };
  unlockMethods: InitUserCryptoMethod[];
  /** Plaintext the account is defined by, and which must therefore never reach the server. */
  rawCryptographicState: {
    userKey: SymmetricKey;
    privateKey: PrivateKey;
    publicKey: PublicKey;
    verifyingKey?: VerifyingKey | null;
  };
  vault?: SeedVault;
}

/**
 * The master-password unlock data the server holds for an account, or `null` when it has none.
 */
export function toMasterPasswordUnlock(vector: SeedAccount): StoredMasterPasswordUnlock | null {
  for (const method of vector.unlockMethods) {
    if (!("masterPasswordUnlock" in method)) {
      continue;
    }

    const unlock = method.masterPasswordUnlock.master_password_unlock;
    return {
      masterKeyWrappedUserKey: asEncString(unlock.masterKeyWrappedUserKey),
      salt: unlock.salt,
      kdf: unlock.kdf,
      containedKeyId: unlock.containedKeyId,
    };
  }

  return null;
}

export interface SeedVault {
  ciphers?: { id: string; encrypted: Cipher; decrypted?: CipherView }[];
  folders?: { id: string; encrypted: Folder; decrypted?: FolderView }[];
}

/** An organization to seed, in the shape the committed test vectors record. */
export interface SeedOrganization {
  organizationId: OrganizationId;
  name: string;
  publicKey?: PublicKey;
  wrappedPrivateKey?: string;
  organizationKeyId?: string | null;
  members: {
    userEmail: string;
    organizationKeySealedToMember: string;
    accountRecoveryKey?: string;
  }[];
  vault?: SeedVault;
}

/** What {@link ApiServer.seedUser} hands back, so a test does not have to dig the account out again. */
export interface SeededAccount {
  userId: AccountId;
  email: string;
  ciphers(): Cipher[];
  folders(): Folder[];
}

/** Where a seeded emergency access grant starts, and what it grants. */
export interface SeedGrant {
  type: EmergencyAccessTypeValue;
  status: EmergencyAccessStatusValue;
  waitTimeDays?: number;
}

/** A seeded emergency access grant, alongside both accounts. */
export interface SeededEmergencyAccess {
  id: string;
  grantor: SeededTestVector;
  grantee: SeededTestVector;
}

/** The invite email a grantee receives: the grant to accept, and the token to accept it with. */
export interface EmergencyAccessInviteEmail {
  id: string;
  token: string;
}

/** A seeded account, alongside the vector it was seeded from. */
export interface SeededTestVector extends SeededAccount {
  /** The vector, for the password and the plaintext it records. */
  vector: UserVector;
  /** The seed account the vector produced, for asserting what the account decrypts to. */
  seed: SeedAccount;
}

export class ServerEmulator {
  /** The rows every service reads and writes. Tests assert on these. */
  readonly db = new Database();

  readonly api = new ApiServer(this.db);
  readonly identity = new IdentityServer(this.db);
  readonly keyConnector = new KeyConnectorServer(this.db);
  readonly emergencyAccess = new EmergencyAccessServer(this.db);

  /** The seeded account with this email. Throws if there is none. */
  getUser(email: string): UserEntity {
    const [user] = this.db.users.filter((candidate) => candidate.email === email);
    if (user === undefined) {
      throw new Error(`no seeded account with email ${email}`);
    }

    return user;
  }

  /**
   * Inserts an account and the vault it owns: its profile and cryptographic state, plus every
   * cipher and folder the vector carries, each owned by that account and in no organization.
   *
   * Returns handles onto the stored rows, so a test reads what the server holds now rather than
   * what the vector held at seed time.
   */
  seedUser(vector: SeedAccount): SeededAccount {
    const { account } = vector;
    const raw = vector.rawCryptographicState;

    const user: UserEntity = {
      userId: asAccountId(fromUuid(account.userId)),
      email: account.email,
      accountCryptographicState: account.accountCryptographicState,
      publicKey: raw.publicKey,
      verifyingKey: raw.verifyingKey ?? null,
      securityVersion: account.securityVersion,
      kdf: account.kdf,
      userKeyId: account.userKeyId,
      masterPasswordUnlock: toMasterPasswordUnlock(vector),
      upgradeToken: account.upgradeToken,
      organizationKeys: account.organizationKeys ?? {},
    };

    this.db.users.set(user.userId, user);

    for (const cipher of vector.vault?.ciphers ?? []) {
      this.db.ciphers.set(cipher.id, {
        userId: user.userId,
        organizationId: null,
        cipher: cipher.encrypted,
      });
    }
    for (const folder of vector.vault?.folders ?? []) {
      this.db.folders.set(folder.id, { userId: user.userId, folder: folder.encrypted });
    }

    return {
      userId: user.userId,
      email: user.email,
      ciphers: () => this.api.vaultFor(user).ciphers,
      folders: () => this.api.vaultFor(user).folders,
    };
  }

  /**
   * Seeds a committed user vector.
   *
   * `modify` rewrites the seed account before it is stored, for a test that needs an account the
   * vector does not record — a server that has not stored a key id yet, say.
   */
  seedUserTestVector(
    vector: UserVector,
    modify: (account: SeedAccount) => SeedAccount = (account) => account,
  ): SeededTestVector {
    const seed = modify(toSeedAccount(vector));

    return { vector, seed, ...this.seedUser(seed) };
  }

  /**
   * Seeds an organization and its members.
   *
   * Members are named by email, as everything else in the harness is, and resolved against the
   * accounts already seeded.
   */
  seedOrganization(vector: SeedOrganization): void {
    const members: OrganizationMember[] = [];

    for (const member of vector.members) {
      const user = this.getUser(member.userEmail);
      members.push({
        userId: user.userId,
        organizationKeySealedToMember: member.organizationKeySealedToMember,
        accountRecoveryKey: member.accountRecoveryKey,
      });
    }

    // The database keys on strings; the seed carries the SDK's id type.
    const organizationId = fromUuid(vector.organizationId);

    this.db.organizations.set(organizationId, {
      organizationId,
      name: vector.name,
      publicKey: vector.publicKey,
      wrappedPrivateKey: vector.wrappedPrivateKey,
      organizationKeyId: vector.organizationKeyId ?? null,
      members,
    });

    for (const cipher of vector.vault?.ciphers ?? []) {
      this.db.ciphers.set(cipher.id, {
        userId: null,
        organizationId,
        // The row and the model have to agree: the response is built from the model.
        cipher: { ...cipher.encrypted, organizationId: vector.organizationId },
      });
    }
  }

  /**
   * Seeds a committed emergency access vector: both accounts, and the grant between them holding
   * the recorded grantor key sealed to the grantee.
   *
   * `grant` picks the lifecycle point, since the vector records only the key: a grant approved
   * for viewing, say, lets a test go straight to decrypting the grantor's vault.
   */
  seedEmergencyAccessTestVector(
    vector: EmergencyAccessVector,
    grant: SeedGrant,
  ): SeededEmergencyAccess {
    const users = testVectors.users.withMasterPassword();
    const grantor = this.seedUserTestVector(users.get(vector.grantorVectorName));
    const grantee = this.seedUserTestVector(users.get(vector.granteeVectorName));

    this.db.emergencyAccess.set(vector.id, {
      id: vector.id,
      grantorId: grantor.userId,
      granteeId: grantee.userId,
      email: grantee.email,
      type: grant.type,
      status: grant.status,
      waitTimeDays: grant.waitTimeDays ?? 1,
      keyEncrypted: vector.grantorUserKeySealedToGrantee,
      inviteToken: "",
    });

    return { id: vector.id, grantor, grantee };
  }

  /** The newest invite sent to `email`. Throws if there is none. */
  inviteEmailFor(email: string): EmergencyAccessInviteEmail {
    const invites = this.db.emergencyAccess.filter((grant) => grant.email === email);
    const invite = invites.at(-1);
    if (invite === undefined) {
      throw new Error(`no emergency access invite was sent to ${email}`);
    }

    return { id: invite.id, token: invite.inviteToken };
  }

  /**
   * Patches `globalThis.fetch` so the SDK's requests reach the model.
   *
   * Every route is bound to the origin its service answers on, so a request aimed at the wrong
   * service is unmatched rather than quietly served by another service's routes. Call `restore()`
   * on the result in `afterEach`, or the patch outlives the test.
   */
  installFetchHook(): HttpMock {
    return installHttpMock({
      ...bindToOrigin(this.api.routes(), API_URL),
      ...bindToOrigin(this.emergencyAccess.routes(), API_URL),
      ...bindToOrigin(this.identity.routes(), IDENTITY_URL),
      ...bindToOrigin(this.keyConnector.routes(), KEY_CONNECTOR_URL),
    });
  }
}
