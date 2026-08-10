// A model of the Bitwarden API: entities, routing, and the write semantics that matter.
//
// It is not a reimplementation of the server, and it does no authentication.
//
// Seeding takes committed test vectors directly, because the entities are the same encrypted domain
// models the vectors record.

import type { Cipher, Folder } from "@bitwarden/sdk-internal";

import type { MockReply, Routes } from "../http-mock";
import type { EmergencyAccessVector, OrganizationVector, UserVector } from "../test-vectors/load";

import { Database, type UserEntity } from "./entities";
import {
  accountsKeysResponse,
  cipherToResponse,
  folderToResponse,
  keyRotationDataResponse,
  kdfFromResponse,
  requestToCipher,
  requestToFolder,
  syncResponse,
} from "./serializers";
import { API_URL } from "./urls";

/** The id the server assigns to a cipher created without one. */
const CREATED_CIPHER_ID = "bc02ff00-0000-4000-8000-000000000000";
/** The id the server assigns to a folder created without one. */
const CREATED_FOLDER_ID = "bc03ff00-0000-4000-8000-000000000000";

const postedList = (value: unknown) => (Array.isArray(value) ? value : null);

export interface SeededAccount {
  userId: string;
  /** How the harness addresses this account: `syncToLocalState(api, account.email, local)`. */
  email: string;
  vector: UserVector;
  /** Every cipher the account currently holds, encrypted, straight out of the database. */
  ciphers(): Cipher[];
  folders(): Folder[];
}

export class ApiServer {
  readonly db = new Database();

  private readonly emergencyAccess: EmergencyAccessVector[] = [];
  private readonly devices = new Map<
    string,
    { encryptedPrivateKey: string; encryptedUserKey: string }
  >();
  private readonly enrollments = new Set<string>();
  private readonly leaks: string[] = [];
  private readonly seeded = new Map<string, UserVector>();

  /** The route table to install. */
  routes(): Routes {
    return {
      // ---- account -------------------------------------------------------------------------
      "GET /sync": () => ({ json: syncResponse(this.db, this.actingUser()) }),
      "GET /accounts/keys": () => ({ json: accountsKeysResponse(this.actingUser()) }),

      // ---- key rotation --------------------------------------------------------------------
      "GET /accounts/key-management/key-rotation-data": () => {
        const user = this.actingUser();
        return {
          json: keyRotationDataResponse(
            this.db,
            user,
            this.emergencyAccess
              .filter((grant) => grant.grantorVector === this.findVectorName(user.userId))
              .map((grant) => ({
                id: grant.id,
                granteeVector: grant.granteeVector,
                granteePublicKey: grant.granteePublicKey,
              })),
          ),
        };
      },

      "POST /accounts/key-management/rotate-user-keys": (request) => {
        this.applyRotation(request.json());
        return {};
      },

      // ---- ciphers -------------------------------------------------------------------------
      "POST /ciphers": (request) => this.createCipher(request.json()),
      "POST /ciphers/create": (request) => {
        const posted = request.json();
        return this.createCipher(posted.cipher ?? posted);
      },
      "PUT /ciphers/:id": (request) => this.updateCipher(request.params.id, request.json()),
      "DELETE /ciphers/:id": (request) => {
        this.db.ciphers.delete(request.params.id);
        return {};
      },
      "PUT /ciphers/:id/delete": (request) => {
        const entry = this.requireCipher(request.params.id);
        entry.cipher = {
          ...(entry.cipher as any),
          deletedDate: this.db.revisions.next(),
          revisionDate: this.db.revisions.current(),
        } as Cipher;
        return {};
      },
      "PUT /ciphers/:id/restore": (request) => {
        const entry = this.requireCipher(request.params.id);
        entry.cipher = {
          ...(entry.cipher as any),
          deletedDate: null,
          revisionDate: this.db.revisions.next(),
        } as Cipher;
        return { json: cipherToResponse(entry.cipher) };
      },

      // ---- attachments ---------------------------------------------------------------------
      "POST /ciphers/:id/attachment/v2": (request) => {
        const entry = this.requireCipher(request.params.id);
        const posted = request.json();
        const attachmentId = `attachment-${this.db.revisions.next().slice(-9, -1)}`;
        const existing = ((entry.cipher as any).attachments ?? []) as any[];

        entry.cipher = {
          ...(entry.cipher as any),
          attachments: [
            ...existing,
            {
              id: attachmentId,
              fileName: posted.fileName,
              key: posted.key,
              size: String(posted.fileSize),
              sizeName: `${posted.fileSize} Bytes`,
              url: null,
            },
          ],
          revisionDate: this.db.revisions.current(),
        } as Cipher;

        return {
          json: {
            attachmentId,
            url: `${API_URL}/attachments/${attachmentId}`,
            fileUploadType: 0,
            // Note the field name: create returns the cipher as `cipherResponse`...
            cipherResponse: cipherToResponse(entry.cipher),
          },
        };
      },
      "DELETE /ciphers/:id/attachment/:attachmentId": (request) => {
        const entry = this.requireCipher(request.params.id);
        const remaining = (((entry.cipher as any).attachments ?? []) as any[]).filter(
          (attachment) => attachment.id !== request.params.attachmentId,
        );
        entry.cipher = {
          ...(entry.cipher as any),
          attachments: remaining.length > 0 ? remaining : null,
          revisionDate: this.db.revisions.next(),
        } as Cipher;
        // ...while delete wraps it as `{ cipher }`. The real API is inconsistent here.
        return { json: { cipher: cipherToResponse(entry.cipher) } };
      },
      "GET /ciphers/:id/attachment/:attachmentId": (request) => ({
        json: {
          id: request.params.attachmentId,
          url: `${API_URL}/download/${request.params.attachmentId}`,
        },
      }),
      "GET /ciphers/:id/attachment/:attachmentId/renew": (request) => ({
        json: { url: `${API_URL}/renewed/${request.params.attachmentId}` },
      }),

      // ---- folders -------------------------------------------------------------------------
      "POST /folders": (request) => {
        const folder = requestToFolder(request.json(), {
          id: CREATED_FOLDER_ID,
          revisionDate: this.db.revisions.next(),
        });
        this.db.folders.set(CREATED_FOLDER_ID, { ownerId: this.actingUser().userId, folder });
        return { json: folderToResponse(folder) };
      },
      "PUT /folders/:id": (request) => {
        const id = request.params.id;
        const entry = this.db.folders.get(id);
        if (entry === undefined) {
          return { status: 404, json: { message: `no folder ${id}` } };
        }
        entry.folder = requestToFolder(request.json(), {
          id,
          revisionDate: this.db.revisions.next(),
        });
        return { json: folderToResponse(entry.folder) };
      },

      // ---- key connector enrolment (the API half; the connector itself is a separate model) --
      "POST /accounts/key-connector/enroll": (request) => {
        this.actingUser().keyConnectorKeyWrappedUserKey =
          request.json().keyConnectorKeyWrappedUserKey;
        return {};
      },
      "POST /accounts/set-key-connector-key": () => ({}),

      // ---- kdf change --------------------------------------------------------------------------
      // Both halves are replaced together. A client that persisted the new KDF without the matching
      // unlock data — or the reverse — could no longer derive the master key that opens the account,
      // so the model refuses to hold one without the other.
      "POST /accounts/kdf": (request) => {
        const posted = request.json();
        const user = this.actingUser();
        if (user.masterPasswordUnlock === null) {
          return { status: 400, json: { message: "account has no master password" } };
        }
        // The change is authenticated with a hash the client derived under the *current* KDF. Without
        // one the real server has nothing to check the request against, so it never applies the change.
        if (
          typeof posted.masterPasswordHash !== "string" ||
          posted.masterPasswordHash.length === 0
        ) {
          return { status: 401, json: { message: "missing master password hash" } };
        }
        const kdf = kdfFromResponse(posted.unlockData.kdf);
        user.kdf = kdf;
        user.masterPasswordUnlock = {
          masterKeyWrappedUserKey: posted.unlockData.masterKeyWrappedUserKey,
          salt: posted.unlockData.salt,
          kdf,
        };
        return {};
      },

      // ---- registration --------------------------------------------------------------------
      // These three deserialize a JSON response model, so an empty body reaches the SDK as
      // `Unsupported(octet-stream)`. Every field on each model is optional, so a stub object is enough.
      "POST /identity/accounts/register/finish": () => ({
        json: { object: "registerFinish" },
      }),
      "POST /accounts/set-password": () => ({}),
      "POST /accounts/keys": () => ({ json: { object: "keys" } }),
      "PUT /accounts/keys": () => ({ json: { object: "keys" } }),
      "PUT /devices/:identifier/keys": (request) => {
        const posted = request.json();
        this.devices.set(request.params.identifier, {
          encryptedPrivateKey: posted.encryptedPrivateKey,
          encryptedUserKey: posted.encryptedUserKey,
        });
        return { json: { object: "device" } };
      },
      "PUT /organizations/:orgId/users/:userId/reset-password-enrollment": (request) => {
        this.enrollments.add(`${request.params.orgId}/${request.params.userId}`);
        const member = this.db.organizations
          .get(request.params.orgId)
          ?.members.get(request.params.userId);
        if (member !== undefined) {
          member.resetPasswordEnrolled = true;
        }
        return {};
      },
    };
  }

  seedUser(vector: UserVector): SeededAccount {
    const userId = vector.account.userId as unknown as string;
    const masterPassword = vector.unlockMethods.find((m) => "masterPasswordUnlock" in m) as
      | {
          masterPasswordUnlock: {
            master_password_unlock: {
              masterKeyWrappedUserKey: { toString(): string };
              salt: string;
            };
          };
        }
      | undefined;

    this.db.users.set(userId, {
      userId,
      email: vector.account.email,
      accountCryptographicState: vector.account.accountCryptographicState,
      publicKey: vector.rawCryptographicState.publicKey,
      verifyingKey: vector.rawCryptographicState.verifyingKey,
      securityVersion: vector.account.securityVersion,
      kdf: vector.account.kdf,
      masterPasswordUnlock:
        masterPassword === undefined
          ? null
          : {
              masterKeyWrappedUserKey:
                masterPassword.masterPasswordUnlock.master_password_unlock.masterKeyWrappedUserKey.toString(),
              salt: masterPassword.masterPasswordUnlock.master_password_unlock.salt,
              kdf: vector.account.kdf,
            },
      credentials: {
        unlockMethods: vector.unlockMethods,
        password: vector.account.password,
        upgradeToken: vector.account.upgradeToken,
        organizationKeys: vector.account.organizationKeys ?? {},
        vectorName: vector.name,
        neverSend: [
          { label: "master password", value: vector.account.password },
          { label: "user key", value: vector.rawCryptographicState.userKey },
          { label: "private key", value: vector.rawCryptographicState.privateKey },
          ...(vector.rawCryptographicState.masterKey === null
            ? []
            : [{ label: "master key", value: vector.rawCryptographicState.masterKey }]),
        ],
      },
      accountRecoveryUnlockData: [],
      emergencyAccessUnlockData: [],
      devices: new Map(),
    });
    this.seeded.set(userId, vector);

    for (const item of vector.vault.ciphers) {
      this.db.ciphers.set(item.id, { ownerId: userId, cipher: item.encrypted });
    }
    for (const item of vector.vault.folders) {
      this.db.folders.set(item.id, { ownerId: userId, folder: item.encrypted });
    }
    for (const item of vector.vault.sends) {
      this.db.sends.set(item.id, { ownerId: userId, send: item.encrypted });
    }

    return {
      userId,
      email: vector.account.email,
      vector,
      ciphers: () => this.db.ciphersFor(userId),
      folders: () => this.db.foldersFor(userId),
    };
  }

  seedOrganization(vector: OrganizationVector): void {
    const organizationId = vector.organizationId as unknown as string;
    this.db.organizations.set(organizationId, {
      organizationId,
      name: vector.name,
      publicKey: vector.publicKey,
      wrappedPrivateKey: vector.wrappedPrivateKey.toString(),
      organizationKeyId: vector.organizationKeyId,
      members: new Map(
        vector.members.map((member) => {
          // Members reference a user vector by name; the id comes from whichever user is seeded.
          const seededMember = [...this.seeded.entries()].find(
            ([, candidate]) => candidate.name === member.userVector,
          );
          return [
            seededMember?.[0] ?? member.userVector,
            {
              userId: seededMember?.[0] ?? member.userVector,
              userVectorName: member.userVector,
              organizationKeySealedToMember: member.organizationKeySealedToMember.toString(),
              accountRecoveryKey: member.accountRecoveryKey?.toString(),
              resetPasswordEnrolled: member.accountRecoveryKey != null,
            },
          ];
        }),
      ),
    });

    // Organization-owned vault items belong to the organization, not to any one member, so they are
    // stored under the organization id as owner and never appear in a member's personal sync.
    for (const item of vector.vault.ciphers) {
      this.db.ciphers.set(item.id, { ownerId: organizationId, cipher: item.encrypted });
    }
  }

  seedEmergencyAccess(vectors: EmergencyAccessVector[]): void {
    this.emergencyAccess.push(...vectors);
  }

  /** The whole encrypted database, for snapshotting or inspection. */
  dump(): Record<string, unknown> {
    return {
      users: [...this.db.users.keys()].map((userId) => this.dumpFor(userId)),
      organizations: [...this.db.organizations.values()].map((organization) => ({
        ...organization,
        members: Object.fromEntries(organization.members),
      })),
      invites: [...this.db.invites.values()],
    };
  }

  /** One account's slice of it. */
  dumpFor(userId: string): Record<string, unknown> {
    const user = this.db.user(userId);
    return {
      user: {
        userId: user.userId,
        email: user.email,
        accountCryptographicState: user.accountCryptographicState,
        publicKey: user.publicKey,
        verifyingKey: user.verifyingKey,
        securityVersion: user.securityVersion,
        masterPasswordUnlock: user.masterPasswordUnlock,
        keyConnectorKeyWrappedUserKey: user.keyConnectorKeyWrappedUserKey ?? null,
        devices: Object.fromEntries(user.devices),
      },
      ciphers: this.db.ciphersFor(userId),
      folders: this.db.foldersFor(userId),
      sends: this.db.sendsFor(userId),
    };
  }

  /** The single seeded account, when there is exactly one. Most tests seed one. */
  soleUserId(): string {
    const ids = [...this.db.users.keys()];
    if (ids.length !== 1) {
      throw new Error(
        `expected exactly one seeded user, found ${ids.length}; pass a user id explicitly`,
      );
    }
    return ids[0];
  }

  /**
   * Device keys posted to `PUT /devices/:identifier/keys`.
   *
   * Held per identifier rather than per user because registration enrols a device for an account that
   * does not exist yet, and because the registration response carries only the device key itself — the
   * wrapped halves are only ever visible here.
   */
  deviceKeys(
    identifier: string,
  ): { encryptedPrivateKey: string; encryptedUserKey: string } | undefined {
    return this.devices.get(identifier);
  }

  /** `${organizationId}/${userId}` for every completed reset-password enrolment. */
  resetPasswordEnrollments(): string[] {
    return [...this.enrollments];
  }

  /**
   * Scans a request body for any seeded account's plaintext secrets and records a violation.
   *
   * Called for every request by {@link installServers}, so no test has to remember to check. Assert
   * {@link secretLeaks} is empty in `afterEach`.
   */
  inspectRequest(route: string, body: string): void {
    if (body === "") {
      return;
    }
    for (const user of this.db.users.values()) {
      for (const secret of user.credentials.neverSend) {
        if (secret.value !== "" && body.includes(secret.value)) {
          this.leaks.push(`${route}: ${secret.label}`);
        }
      }
    }
  }

  /** Every secret that reached the wire, as `<route>: <label>`. Must always be empty. */
  secretLeaks(): string[] {
    return [...this.leaks];
  }

  /** Which account a request belongs to. There is no auth, so the sole seeded user is assumed. */
  private actingUser(): UserEntity {
    return this.db.user(this.soleUserId());
  }

  /**
   * Rejects a write whose `lastKnownRevisionDate` is behind what the server holds.
   *
   * Returns a reply to send, or `undefined` to carry on. A write that carries no revision at all is
   * allowed through: creates do not have one.
   */
  private staleWrite(stored: any | undefined, posted: any): MockReply | undefined {
    if (stored === undefined || posted.lastKnownRevisionDate == null) {
      return undefined;
    }
    const sent = new Date(posted.lastKnownRevisionDate).getTime();
    const held = new Date(stored.revisionDate).getTime();
    if (sent < held) {
      return {
        status: 409,
        json: {
          message: "The item has changed since you loaded it.",
          object: "error",
          validationErrors: {},
        },
      };
    }
    return undefined;
  }

  private requireCipher(id: string) {
    const entry = this.db.ciphers.get(id);
    if (entry === undefined) {
      throw new Error(`no cipher ${id} in the model server`);
    }
    return entry;
  }

  private createCipher(posted: any): MockReply {
    const cipher = requestToCipher(posted, undefined, {
      id: CREATED_CIPHER_ID,
      revisionDate: this.db.revisions.next(),
    });
    this.db.ciphers.set(CREATED_CIPHER_ID, { ownerId: this.actingUser().userId, cipher });
    return { json: cipherToResponse(cipher) };
  }

  private updateCipher(id: string, posted: any): MockReply {
    const entry = this.db.ciphers.get(id);
    if (entry === undefined) {
      return { status: 404, json: { message: `no cipher ${id}` } };
    }

    const conflict = this.staleWrite(entry.cipher, posted);
    if (conflict !== undefined) {
      return conflict;
    }

    entry.cipher = requestToCipher(posted, entry.cipher, {
      id,
      revisionDate: this.db.revisions.next(),
    });
    return { json: cipherToResponse(entry.cipher) };
  }

  /**
   * Absorbs a completed key rotation.
   *
   * This is the whole reason the server holds state: the rotated account keys, unlock data and
   * re-encrypted vault all land here, and the next rotation reads them back from `GET /sync`.
   */
  private applyRotation(posted: any): void {
    const user = this.actingUser();
    const state = posted.wrappedAccountCryptographicState;

    // A rotation always lands on a V2 state, whatever the account started as.
    user.accountCryptographicState = {
      V2: {
        private_key: state.publicKeyEncryptionKeyPair.wrappedPrivateKey,
        signed_public_key: state.publicKeyEncryptionKeyPair.signedPublicKey,
        signing_key: state.signatureKeyPair.wrappedSigningKey,
        security_state: state.securityState.securityState,
      },
    };
    user.publicKey = state.publicKeyEncryptionKeyPair.publicKey;
    user.verifyingKey = state.signatureKeyPair.verifyingKey;
    user.securityVersion = state.securityState.securityVersion;

    // Recorded so tests can assert on the account rather than on the request that produced it.
    if (posted.unlockMethodData?.unlockMethod != null) {
      user.unlockMethod = posted.unlockMethodData.unlockMethod;
    }
    user.accountRecoveryUnlockData =
      postedList(posted.unlockData?.organizationAccountRecoveryUnlockData) ?? [];
    user.emergencyAccessUnlockData = postedList(posted.unlockData?.emergencyAccessUnlockData) ?? [];

    const unlock = posted.unlockMethodData?.masterPasswordUnlockData;
    if (unlock != null) {
      user.masterPasswordUnlock = {
        masterKeyWrappedUserKey: unlock.masterKeyWrappedUserKey,
        salt: unlock.salt,
        kdf: kdfFromResponse(unlock.kdf),
      };
    }

    // A key-connector rotation re-wraps the user key with the same connector key and posts it here, so
    // recording it is what lets a key-connector account be re-opened from the server after rotating.
    const keyConnectorWrapped = posted.unlockMethodData?.keyConnectorKeyWrappedUserKey;
    if (keyConnectorWrapped != null) {
      user.keyConnectorKeyWrappedUserKey = keyConnectorWrapped;
    }

    for (const cipher of (postedList(posted.accountData?.ciphers) ?? []) as any[]) {
      const entry = this.db.ciphers.get(cipher.id);
      this.db.ciphers.set(cipher.id, {
        ownerId: user.userId,
        cipher: requestToCipher(cipher, entry?.cipher, {
          id: cipher.id,
          revisionDate: this.db.revisions.next(),
        }),
      });
    }
    for (const folder of (postedList(posted.accountData?.folders) ?? []) as any[]) {
      this.db.folders.set(folder.id, {
        ownerId: user.userId,
        folder: requestToFolder(folder, {
          id: folder.id,
          revisionDate: this.db.revisions.next(),
        }),
      });
    }
    for (const send of (postedList(posted.accountData?.sends) ?? []) as any[]) {
      const entry = this.db.sends.get(send.id);
      this.db.sends.set(send.id, {
        ownerId: user.userId,
        send: { ...(entry?.send as any), ...send },
      });
    }
  }

  private findVectorName(userId: string): string | undefined {
    return this.seeded.get(userId)?.name;
  }
}
