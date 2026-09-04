// An in-memory model of the Bitwarden API.
//
// Tests seed accounts and vaults into it, install its routes over `fetch`, and then assert on what
// the server ends up holding rather than on what the client sent. A request body shows what the
// client intended; the stored account shows what a user has to live with afterwards.
//
// Two rules are modelled here rather than asserted in tests, so a client that gets them wrong fails
// the operation itself: a write carrying a stale revision is rejected, and every request body is
// checked for plaintext no client may ever send.

import type { Cipher, CipherView, Folder, FolderView } from "@bitwarden/sdk-internal";

import type { MockReply, Routes } from "../http-mock";
import { asEncString } from "../type-assertion-helpers";

import { Database } from "./database";
import type { ChangeKdfRequest, CipherRequest, ErrorResponse, FolderRequest } from "./dto";
import type { OrganizationMember, UserEntity } from "./entities";
import {
  accountKeysResponse,
  cipherToResponse,
  folderToResponse,
  requestToCipher,
  requestToFolder,
  syncResponse,
  unlockDataFromRequest,
} from "./serializers";

const HTTP_BAD_REQUEST = 400;
const HTTP_NOT_FOUND = 404;
const HTTP_CONFLICT = 409;

/** An account to seed, in the shape the committed test vectors record. */
export interface SeedAccount {
  /** The vector's slug. Used in error messages and to cross-reference organization members. */
  name: string;
  account: {
    userId: string;
    email: string;
    password: string;
    kdf: UserEntity["kdf"];
    securityVersion: number;
    accountCryptographicState: UserEntity["accountCryptographicState"];
    upgradeToken?: UserEntity["credentials"]["upgradeToken"];
    organizationKeys?: Record<string, string>;
  };
  unlockMethods: UserEntity["credentials"]["unlockMethods"];
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
 * A vault as a vector records it: the ciphertext the server serves, and the plaintext it must
 * decrypt to.
 */
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
    userVector: string;
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

function error(status: number, message: string): MockReply {
  const body: ErrorResponse = { message };
  return { status, json: body };
}

export class ApiServer {
  readonly db = new Database();

  /** Bodies that carried plaintext no client may send, as `"<route>: <label>"`. */
  private readonly leaks: string[] = [];

  /** The account requests are attributed to. Set by seeding, changed with {@link actAs}. */
  private acting: string | undefined;

  /**
   * Attributes subsequent requests to `email`.
   *
   * The mock has no bearer token to read, so the acting identity is carried explicitly. Seeding the
   * first account sets it; a test with more than one account switches between them.
   */
  actAs(email: string): void {
    this.acting = this.db.userByEmail(email).userId;
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
      masterPasswordUnlock: masterPasswordUnlockOf(vector),
      credentials: {
        unlockMethods: vector.unlockMethods,
        password: account.password,
        ...(account.upgradeToken === undefined ? {} : { upgradeToken: account.upgradeToken }),
        organizationKeys: account.organizationKeys ?? {},
        vectorName: vector.name,
        neverSend: [
          { label: "password", value: account.password },
          { label: "user key", value: raw.userKey },
          { label: "private key", value: raw.privateKey },
          ...(raw.masterKey === null ? [] : [{ label: "master key", value: raw.masterKey }]),
        ].filter((secret) => secret.value !== ""),
      },
    };

    this.db.users.set(user.userId, user);
    this.acting ??= user.userId;

    for (const cipher of vector.vault?.ciphers ?? []) {
      this.db.ciphers.set(cipher.id, user.userId, cipher.encrypted);
    }
    for (const folder of vector.vault?.folders ?? []) {
      this.db.folders.set(folder.id, user.userId, folder.encrypted);
    }

    return {
      userId: user.userId,
      email: user.email,
      ciphers: () => this.db.ciphers.for(user.userId),
      folders: () => this.db.folders.for(user.userId),
    };
  }

  /**
   * Seeds an organization and its members.
   *
   * Members are named by vector slug rather than by id, matching how the committed organization
   * vectors reference them, and are resolved against the accounts already seeded.
   */
  seedOrganization(vector: SeedOrganization): void {
    const members = new Map<string, OrganizationMember>();

    for (const member of vector.members) {
      const user = this.userByVectorName(member.userVector);
      members.set(user.userId, {
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
      this.db.ciphers.set(cipher.id, vector.organizationId, cipher.encrypted);
    }
  }

  routes(): Routes {
    return {
      "GET /sync": () => ({ json: syncResponse(this.db, this.actingUser()) }),
      "GET /accounts/keys": () => ({ json: accountKeysResponse(this.actingUser()) }),

      "POST /accounts/kdf": (request) => this.changeKdf(request.json<ChangeKdfRequest>()),

      "POST /ciphers": (request) => this.createCipher(request.json<CipherRequest>()),
      "POST /ciphers/create": (request) => this.createCipher(request.json<CipherRequest>()),
      "PUT /ciphers/:id": (request) =>
        this.updateCipher(request.params.id, request.json<CipherRequest>()),
      "DELETE /ciphers/:id": (request) => this.deleteCipher(request.params.id),
      "PUT /ciphers/:id/delete": (request) => this.softDeleteCipher(request.params.id),
      "PUT /ciphers/:id/restore": (request) => this.restoreCipher(request.params.id),

      "POST /folders": (request) => this.createFolder(request.json<FolderRequest>()),
      "PUT /folders/:id": (request) =>
        this.updateFolder(request.params.id, request.json<FolderRequest>()),
    };
  }

  /**
   * Records any seeded account's password, user key, private key or master key found in `body`.
   *
   * Called for every request, including ones no route matched, so a leak on an unexpected endpoint
   * is caught too.
   */
  inspectRequest(route: string, body: string): void {
    if (body === "") {
      return;
    }
    for (const user of this.db.users.values()) {
      for (const secret of user.credentials.neverSend) {
        if (body.includes(secret.value)) {
          this.leaks.push(`${route}: ${secret.label} of ${user.email}`);
        }
      }
    }
  }

  /** Assert this is empty in `afterEach`. */
  secretLeaks(): string[] {
    return [...this.leaks];
  }

  /** The whole database, for byte-stability checks and debugging. */
  dump(): unknown {
    return {
      users: [...this.db.users.values()].map((user) => ({
        ...user,
        credentials: { vectorName: user.credentials.vectorName },
      })),
      organizations: [...this.db.organizations.values()].map((organization) => ({
        ...organization,
        members: [...organization.members.values()],
      })),
      ciphers: this.db.ciphers.all(),
      folders: this.db.folders.all(),
    };
  }

  private actingUser(): UserEntity {
    if (this.acting === undefined) {
      throw new Error("no acting user; seed an account or call actAs first");
    }
    return this.db.user(this.acting);
  }

  private userByVectorName(name: string): UserEntity {
    for (const user of this.db.users.values()) {
      if (user.credentials.vectorName === name) {
        return user;
      }
    }
    throw new Error(`no seeded account from vector ${name}`);
  }

  private changeKdf(posted: ChangeKdfRequest): MockReply {
    const user = this.actingUser();

    if (posted.masterPasswordHash === "") {
      return error(HTTP_BAD_REQUEST, "master password hash required");
    }
    if (user.masterPasswordUnlock === null) {
      return error(HTTP_BAD_REQUEST, "account has no master password");
    }

    user.masterPasswordUnlock = unlockDataFromRequest(posted.unlockData);
    user.kdf = user.masterPasswordUnlock.kdf;
    this.db.revisions.next();
    return {};
  }

  /**
   * 409 when `posted` was written against a revision older than the stored one.
   *
   * Modelled here so a client that edits from stale data fails the write, instead of every test
   * having to notice it did not.
   */
  private staleWrite(
    stored: { revisionDate: string },
    posted: CipherRequest,
  ): MockReply | undefined {
    const known = posted.lastKnownRevisionDate;
    if (known === null || known === undefined) {
      return undefined;
    }
    if (Date.parse(known) < Date.parse(stored.revisionDate)) {
      return error(HTTP_CONFLICT, "the item has changed since it was read");
    }
    return undefined;
  }

  private createCipher(posted: CipherRequest): MockReply {
    const id = this.db.ciphers.newId();
    const now = this.db.revisions.next();
    const cipher = requestToCipher(posted, undefined, {
      id,
      creationDate: now,
      revisionDate: now,
      deletedDate: null,
    });

    this.db.ciphers.set(id, this.actingUser().userId, cipher);
    return { json: cipherToResponse(cipher) };
  }

  private updateCipher(id: string, posted: CipherRequest): MockReply {
    const previous = this.db.ciphers.get(id);
    if (previous === undefined) {
      return error(HTTP_NOT_FOUND, `no cipher ${id}`);
    }

    const stale = this.staleWrite(previous, posted);
    if (stale !== undefined) {
      return stale;
    }

    const cipher = requestToCipher(posted, previous, {
      id,
      creationDate: previous.creationDate,
      revisionDate: this.db.revisions.next(),
      deletedDate: previous.deletedDate ?? null,
    });

    this.db.ciphers.update(id, cipher);
    return { json: cipherToResponse(cipher) };
  }

  private deleteCipher(id: string): MockReply {
    if (this.db.ciphers.get(id) === undefined) {
      return error(HTTP_NOT_FOUND, `no cipher ${id}`);
    }
    this.db.ciphers.remove(id);
    return {};
  }

  private softDeleteCipher(id: string): MockReply {
    return this.restamp(id, this.db.revisions.next());
  }

  private restoreCipher(id: string): MockReply {
    return this.restamp(id, null);
  }

  /** Sets or clears a cipher's `deletedDate` and bumps its revision. */
  private restamp(id: string, deletedDate: string | null): MockReply {
    const cipher = this.db.ciphers.get(id);
    if (cipher === undefined) {
      return error(HTTP_NOT_FOUND, `no cipher ${id}`);
    }

    const updated: Cipher = {
      ...cipher,
      deletedDate: deletedDate ?? undefined,
      revisionDate: this.db.revisions.next(),
    };
    this.db.ciphers.update(id, updated);
    return { json: cipherToResponse(updated) };
  }

  private createFolder(posted: FolderRequest): MockReply {
    const id = this.db.folders.newId();
    const folder = requestToFolder(posted, id, this.db.revisions.next());
    this.db.folders.set(id, this.actingUser().userId, folder);
    return { json: folderToResponse(folder) };
  }

  private updateFolder(id: string, posted: FolderRequest): MockReply {
    if (this.db.folders.get(id) === undefined) {
      return error(HTTP_NOT_FOUND, `no folder ${id}`);
    }
    const folder = requestToFolder(posted, id, this.db.revisions.next());
    this.db.folders.update(id, folder);
    return { json: folderToResponse(folder) };
  }
}

/** The master-password unlock method a vector declares, as the server stores it. */
function masterPasswordUnlockOf(vector: SeedAccount): UserEntity["masterPasswordUnlock"] {
  for (const method of vector.unlockMethods) {
    if ("masterPasswordUnlock" in method) {
      const unlock = method.masterPasswordUnlock.master_password_unlock;
      return {
        masterKeyWrappedUserKey: asEncString(unlock.masterKeyWrappedUserKey),
        salt: unlock.salt,
        kdf: unlock.kdf,
        ...(unlock.containedKeyId === undefined ? {} : { containedKeyId: unlock.containedKeyId }),
      };
    }
  }
  return null;
}
