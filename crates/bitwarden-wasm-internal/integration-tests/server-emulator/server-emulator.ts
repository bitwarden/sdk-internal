// The emulated backend as one object: the stored rows, the API model over them, and the `fetch`
// hook that connects the emulator to the SDK's HTTP client.

import { ApiServer } from "./api-server";
import { Database } from "./database";
import type { OrganizationMember, StoredMasterPasswordUnlock, UserEntity } from "./entities";
import { installHttpMock, type HttpMock, type Routes } from "./http-mock";
import { IdentityServer } from "./identity-server";
import { KeyConnectorServer } from "./key-connector-server";
import { API_URL, IDENTITY_URL, KEY_CONNECTOR_URL } from "./urls";

import { asEncString, asOrganizationId } from "../tests/type-assertion-helpers";

import type {
  Cipher,
  CipherView,
  Folder,
  FolderView,
  InitUserCryptoMethod,
  Kdf,
  KeyId,
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
    userId: string;
    email: string;
    kdf: Kdf;
    userKeyId?: KeyId;
    securityVersion: number;
    accountCryptographicState: WrappedAccountCryptographicState;
    upgradeToken?: V2UpgradeToken;
    organizationKeys?: Record<string, string>;
  };
  unlockMethods: InitUserCryptoMethod[];
  /**
   * The master password authentication hash the identity service compares against.
   *
   * Absent for an account with no master password.
   */
  masterPasswordAuthenticationHash?: string;
  /** Plaintext the account is defined by, and which must therefore never reach the server. */
  rawCryptographicState: {
    userKey: string;
    masterKey: string | null;
    privateKey: string;
    publicKey: string;
    verifyingKey?: string | null;
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
      ...(unlock.containedKeyId === undefined ? {} : { containedKeyId: unlock.containedKeyId }),
    };
  }

  return null;
}

/**
 * The key-connector key an account's deployment holds, or `null` when it uses no key connector.
 *
 * The key travels in the vector's `keyConnector` unlock method, where it stands in for what a real
 * client fetches from the deployment.
 */
export function toKeyConnectorKey(vector: SeedAccount): string | null {
  for (const method of vector.unlockMethods) {
    if ("keyConnector" in method) {
      return method.keyConnector.master_key;
    }
  }

  return null;
}

export interface SeedVault {
  ciphers?: { id: string; encrypted: Cipher; decrypted?: CipherView }[];
  folders?: { id: string; encrypted: Folder; decrypted?: FolderView }[];
}

/** An organization to seed, in the shape the committed test vectors record. */
export interface SeedOrganization {
  organizationId: string;
  name: string;
  publicKey: string;
  wrappedPrivateKey: string;
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
  userId: string;
  email: string;
  ciphers(): Cipher[];
  folders(): Folder[];
}

export class ServerEmulator {
  /** The rows every service reads and writes. Tests assert on these. */
  readonly db = new Database();

  readonly api = new ApiServer(this.db);
  readonly identity = new IdentityServer(this.db);
  readonly keyConnector = new KeyConnectorServer(this.db);

  /** The seeded account with this email. Throws if there is none. */
  getUser(email: string): UserEntity {
    const [user] = this.db.users.filter((candidate) => candidate.email === email);
    if (user === undefined) {
      throw new Error(`no seeded account with email ${email}`);
    }

    return user;
  }

  seedUser(vector: SeedAccount): SeededAccount {
    const { account } = vector;
    const raw = vector.rawCryptographicState;

    const user: UserEntity = {
      userId: account.userId,
      email: account.email,
      accountCryptographicState: account.accountCryptographicState,
      publicKey: raw.publicKey,
      verifyingKey: raw.verifyingKey ?? null,
      securityVersion: account.securityVersion,
      kdf: account.kdf,
      ...(account.userKeyId === undefined ? {} : { userKeyId: account.userKeyId }),
      masterPasswordUnlock: toMasterPasswordUnlock(vector),
      masterPasswordAuthenticationHash: vector.masterPasswordAuthenticationHash ?? null,
      ...(account.upgradeToken === undefined ? {} : { upgradeToken: account.upgradeToken }),
      organizationKeys: account.organizationKeys ?? {},
    };

    this.db.users.set(user.userId, user);

    // A key-connector account's deployment already holds its key, as it would for a real account.
    const keyConnectorKey = toKeyConnectorKey(vector);
    if (keyConnectorKey !== null) {
      this.keyConnector.seedUserKey(user.email, keyConnectorKey);
    }

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
        ...(member.accountRecoveryKey === undefined
          ? {}
          : { accountRecoveryKey: member.accountRecoveryKey }),
      });
    }

    this.db.organizations.set(vector.organizationId, {
      organizationId: vector.organizationId,
      name: vector.name,
      publicKey: vector.publicKey,
      wrappedPrivateKey: vector.wrappedPrivateKey,
      organizationKeyId: vector.organizationKeyId ?? null,
      members,
    });

    for (const cipher of vector.vault?.ciphers ?? []) {
      this.db.ciphers.set(cipher.id, {
        userId: null,
        organizationId: vector.organizationId,
        // The row and the model have to agree: the response is built from the model.
        cipher: { ...cipher.encrypted, organizationId: asOrganizationId(vector.organizationId) },
      });
    }
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
      ...bindToOrigin(this.identity.routes(), IDENTITY_URL),
      ...bindToOrigin(this.keyConnector.routes(), KEY_CONNECTOR_URL),
    });
  }
}
