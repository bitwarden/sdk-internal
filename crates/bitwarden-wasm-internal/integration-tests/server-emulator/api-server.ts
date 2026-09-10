// An in-memory model of the Bitwarden's api server

import type { Cipher, Folder, WrappedAccountCryptographicState } from "@bitwarden/sdk-internal";

import type { MockReply, Routes } from "./http-mock";

import {
  asEncString,
  asKeyId,
  asSignedPublicKey,
  asSignedSecurityState,
  asString,
} from "../tests/type-assertion-helpers";

import { authenticatedRoute } from "./authentication";

/**
 * The floor the server puts under PBKDF2, which is stricter than the SDK's own.
 *
 * An account seeded with fewer iterations predates the rule, as a real one can; the rule only
 * applies to a KDF a client asks to change *to*.
 */
const PBKDF2_MIN_ITERATIONS = 600_000;

/** Key ids travel as a lowercase hex encoding of 16 bytes. */
const KEY_ID_PATTERN = /^[0-9a-f]{32}$/;
import { Database } from "./database";
import {
  AccountKeysRequest,
  AccountKeysResponse,
  type CipherCreateRequest,
  CipherRequest,
  CipherResponse,
  FolderRequest,
  FolderResponse,
  DeviceKeysRequest,
  KdfType,
  KeyConnectorEnrollmentRequest,
  KeyRegenerationRequest,
  KeysRequest,
  KeyRotationDataResponse,
  MasterPasswordUnlockDataModel,
  ResetPasswordEnrollmentRequest,
  RotateUserKeysRequest,
  SetInitialPasswordRequest,
  SetKeyConnectorKeyRequest,
  SyncResponse,
  UserKeyIdRequest,
  type ChangeKdfRequest,
} from "./dto";
import type { CipherEntity, UserEntity } from "./entities";
import { error, HTTP_BAD_REQUEST, HTTP_CONFLICT, HTTP_NOT_FOUND } from "./replies";

/**
 * The parts of an account's V2 state, from the key material a registration posted.
 *
 * `undefined` when the posted keys are incomplete: a registration always builds a V2 state, so a
 * missing signature key pair or security state is a malformed request rather than a V1 account.
 */
function toV2State(keys: AccountKeysRequest):
  | {
      accountCryptographicState: WrappedAccountCryptographicState;
      publicKey: string;
      verifyingKey: string;
      securityVersion: number;
    }
  | undefined {
  const { publicKeyEncryptionKeyPair: pair, signatureKeyPair, securityState } = keys;
  if (pair === undefined || signatureKeyPair === undefined || securityState === undefined) {
    return undefined;
  }
  if (pair.signedPublicKey === undefined) {
    return undefined;
  }

  return {
    accountCryptographicState: {
      V2: {
        private_key: asEncString(pair.wrappedPrivateKey),
        signing_key: asEncString(signatureKeyPair.wrappedSigningKey),
        security_state: asSignedSecurityState(securityState.securityState),
        signed_public_key: asSignedPublicKey(pair.signedPublicKey),
      },
    },
    publicKey: pair.publicKey,
    verifyingKey: signatureKeyPair.verifyingKey,
    securityVersion: securityState.securityVersion,
  };
}

export class ApiServer {
  constructor(readonly db: Database) {}

  routes(): Routes {
    return {
      "GET /sync": authenticatedRoute(this.db, (user) => ({
        json: SyncResponse.forUser(user, this.vaultFor(user)),
      })),
      "GET /accounts/keys": authenticatedRoute(this.db, (user) => ({
        json: AccountKeysResponse.fromUser(user),
      })),

      "POST /accounts/kdf": authenticatedRoute(this.db, (user, request) =>
        this.changeKdf(user, request.json<ChangeKdfRequest>()),
      ),

      "POST /accounts/keys": authenticatedRoute(this.db, (user, request) =>
        this.setAccountKeys(user, request.json<KeysRequest>()),
      ),

      "POST /accounts/set-password": authenticatedRoute(this.db, (user, request) =>
        this.setInitialPassword(user, request.json<SetInitialPasswordRequest>()),
      ),

      "PUT /organizations/:orgId/users/:userId/reset-password-enrollment": authenticatedRoute(
        this.db,
        (user, request) =>
          this.enrollAccountRecovery(
            user,
            request.params.orgId,
            request.json<ResetPasswordEnrollmentRequest>(),
          ),
      ),

      "PUT /devices/:identifier/keys": authenticatedRoute(this.db, (user, request) =>
        this.trustDevice(user, request.params.identifier, request.json<DeviceKeysRequest>()),
      ),

      "POST /accounts/set-key-connector-key": authenticatedRoute(this.db, (user, request) =>
        this.setKeyConnectorKey(user, request.json<SetKeyConnectorKeyRequest>()),
      ),

      "POST /accounts/key-connector/enroll": authenticatedRoute(this.db, (user, request) =>
        this.enrollToKeyConnector(user, request.json<KeyConnectorEnrollmentRequest>()),
      ),

      "POST /accounts/key-management/user-key-id": authenticatedRoute(this.db, (user, request) =>
        this.recordUserKeyId(user, request.json<UserKeyIdRequest>()),
      ),

      "POST /accounts/key-management/regenerate-keys": authenticatedRoute(
        this.db,
        (user, request) => this.regenerateKeys(user, request.json<KeyRegenerationRequest>()),
      ),

      "GET /accounts/key-management/key-rotation-data": authenticatedRoute(this.db, () => ({
        json: KeyRotationDataResponse.empty(),
      })),

      "POST /accounts/key-management/rotate-user-keys": authenticatedRoute(
        this.db,
        (user, request) => this.rotateUserKeys(user, request.json<RotateUserKeysRequest>()),
      ),

      "POST /ciphers": authenticatedRoute(this.db, (user, request) =>
        this.createCipher(user, request.json<CipherRequest>(), []),
      ),
      // A create into collections posts a different body: the cipher nested under the ids.
      "POST /ciphers/create": authenticatedRoute(this.db, (user, request) => {
        const posted = request.json<CipherCreateRequest>();
        return this.createCipher(user, posted.cipher, posted.collectionIds ?? []);
      }),
      "PUT /ciphers/:id": authenticatedRoute(this.db, (user, request) =>
        this.updateCipher(user, request.params.id, request.json<CipherRequest>()),
      ),
      "DELETE /ciphers/:id": authenticatedRoute(this.db, (user, request) =>
        this.deleteCipher(user, request.params.id),
      ),
      "PUT /ciphers/:id/delete": authenticatedRoute(this.db, (user, request) =>
        this.restamp(user, request.params.id, this.db.revisions.next()),
      ),
      "PUT /ciphers/:id/restore": authenticatedRoute(this.db, (user, request) =>
        this.restamp(user, request.params.id, null),
      ),

      "POST /folders": authenticatedRoute(this.db, (user, request) =>
        this.createFolder(user, request.json<FolderRequest>()),
      ),
      "PUT /folders/:id": authenticatedRoute(this.db, (user, request) =>
        this.updateFolder(user, request.params.id, request.json<FolderRequest>()),
      ),
    };
  }

  /** The whole database, for byte-stability checks and debugging. */
  dump(): unknown {
    return {
      users: this.db.users.all(),
      organizations: this.db.organizations.all(),
      ciphers: this.db.ciphers.all(),
      folders: this.db.folders.all(),
    };
  }

  /**
   * The vault `user` can reach: their own items, plus the ciphers of every organization they are a
   * member of. Folders are personal, so only their own.
   */
  vaultFor(user: UserEntity): { ciphers: Cipher[]; folders: Folder[] } {
    return {
      ciphers: this.db.ciphers
        .filter((entity) => this.canReach(user, entity))
        .map((entity) => entity.cipher),
      folders: this.db.folders
        .filter((entity) => entity.userId === user.userId)
        .map((entity) => entity.folder),
    };
  }

  /** Whether `user` owns the cipher or is a member of the organization that does. */
  private canReach(user: UserEntity, entity: CipherEntity): boolean {
    if (entity.userId !== null) {
      return entity.userId === user.userId;
    }

    const organization =
      entity.organizationId === null ? undefined : this.db.organizations.get(entity.organizationId);

    return organization?.members.some((member) => member.userId === user.userId) === true;
  }

  /** A cipher `user` can reach, or `undefined` — which a handler answers 404 for. */
  private reachableCipher(user: UserEntity, id: string): CipherEntity | undefined {
    const entity = this.db.ciphers.get(id);

    return entity !== undefined && this.canReach(user, entity) ? entity : undefined;
  }

  private changeKdf(user: UserEntity, posted: ChangeKdfRequest): MockReply {
    if (posted.masterPasswordHash === "") {
      return error(HTTP_BAD_REQUEST, "master password hash required");
    }
    if (user.masterPasswordUnlock === null) {
      return error(HTTP_BAD_REQUEST, "account has no master password");
    }

    const { kdf } = posted.unlockData;
    if (kdf.kdfType === KdfType.pbkdf2Sha256 && kdf.iterations < PBKDF2_MIN_ITERATIONS) {
      return error(HTTP_BAD_REQUEST, `pbkdf2 iterations must be at least ${PBKDF2_MIN_ITERATIONS}`);
    }

    user.masterPasswordUnlock = MasterPasswordUnlockDataModel.toStored(posted.unlockData);
    user.kdf = user.masterPasswordUnlock.kdf;
    this.db.revisions.next();
    return {};
  }

  /**
   * Provisions key material onto an account that has none.
   *
   * A TDE account is created by SSO before it has any keys, so this is where its cryptographic
   * state first arrives. The account has no unlock method until a later call gives it one.
   */
  private setAccountKeys(user: UserEntity, posted: KeysRequest): MockReply {
    const state = toV2State(posted.accountKeys);
    if (state === undefined) {
      return error(HTTP_BAD_REQUEST, "incomplete account keys");
    }

    user.accountCryptographicState = state.accountCryptographicState;
    user.publicKey = state.publicKey;
    user.verifyingKey = state.verifyingKey;
    user.securityVersion = state.securityVersion;
    if (posted.userKeyId !== undefined) {
      if (!KEY_ID_PATTERN.test(posted.userKeyId)) {
        return error(HTTP_BAD_REQUEST, `malformed key id ${posted.userKeyId}`);
      }
      user.userKeyId = asKeyId(posted.userKeyId);
    }
    this.db.revisions.next();

    // Unlike the other key-management routes, this one answers with the account's keys.
    return { json: AccountKeysResponse.fromUser(user) };
  }

  /**
   * Gives an SSO-provisioned account its first master password.
   *
   * Unlike a registration, the account already exists; unlike a password change, it has no unlock
   * data to replace.
   */
  private setInitialPassword(user: UserEntity, posted: SetInitialPasswordRequest): MockReply {
    if (user.masterPasswordUnlock !== null) {
      return error(HTTP_BAD_REQUEST, "account already has a master password");
    }

    const state = toV2State(posted.accountKeys);
    if (state === undefined) {
      return error(HTTP_BAD_REQUEST, "incomplete account keys");
    }

    user.accountCryptographicState = state.accountCryptographicState;
    user.publicKey = state.publicKey;
    user.verifyingKey = state.verifyingKey;
    user.securityVersion = state.securityVersion;
    user.masterPasswordUnlock = MasterPasswordUnlockDataModel.toStored(posted.masterPasswordUnlock);
    user.kdf = user.masterPasswordUnlock.kdf;
    user.masterPasswordAuthenticationHash =
      posted.masterPasswordAuthentication.masterPasswordAuthenticationHash;
    this.db.revisions.next();

    return {};
  }

  /**
   * Records the account's user key sealed to an organization's account-recovery public key.
   *
   * Held against the membership rather than the account: recovery is the organization's capability,
   * and a user enrolled in one organization is not enrolled in another.
   */
  private enrollAccountRecovery(
    user: UserEntity,
    organizationId: string,
    posted: ResetPasswordEnrollmentRequest,
  ): MockReply {
    const organization = this.db.organizations.get(organizationId);
    const member = organization?.members.find((candidate) => candidate.userId === user.userId);
    if (member === undefined) {
      return error(HTTP_NOT_FOUND, `no membership of ${organizationId} for this account`);
    }
    if (posted.resetPasswordKey === undefined) {
      return error(HTTP_BAD_REQUEST, "reset password key required");
    }

    member.accountRecoveryKey = posted.resetPasswordKey;
    this.db.revisions.next();

    return {};
  }

  /** Records the keys that let a device unlock the account without a password. */
  private trustDevice(user: UserEntity, identifier: string, posted: DeviceKeysRequest): MockReply {
    user.trustedDeviceKeys = {
      ...user.trustedDeviceKeys,
      [identifier]: {
        deviceProtectedUserKey: posted.encryptedUserKey,
        protectedDevicePublicKey: posted.encryptedPublicKey,
        protectedDevicePrivateKey: posted.encryptedPrivateKey,
      },
    };
    this.db.revisions.next();

    return { json: { id: this.db.deviceIds.next(), object: "device" } };
  }

  /**
   * Gives an SSO-provisioned account its first key material and key-connector unlock at once.
   *
   * Distinct from {@link enrollToKeyConnector}, which moves an *existing* account with a master
   * password onto key connector: this account never had one.
   */
  private setKeyConnectorKey(user: UserEntity, posted: SetKeyConnectorKeyRequest): MockReply {
    const state = toV2State(posted.accountKeys);
    if (state === undefined) {
      return error(HTTP_BAD_REQUEST, "incomplete account keys");
    }

    user.accountCryptographicState = state.accountCryptographicState;
    user.publicKey = state.publicKey;
    user.verifyingKey = state.verifyingKey;
    user.securityVersion = state.securityVersion;
    user.keyConnectorKeyWrappedUserKey = asEncString(posted.keyConnectorKeyWrappedUserKey);
    user.masterPasswordUnlock = null;
    this.db.revisions.next();

    return {};
  }

  /**
   * Moves an account onto key-connector unlock.
   *
   * The key-connector-wrapped user key replaces the master-password unlock data: an enrolled
   * account no longer has a master password, so `GET /sync` must stop reporting one. The KDF
   * settings stay, since the account still needs them to initialize.
   */
  private enrollToKeyConnector(user: UserEntity, posted: KeyConnectorEnrollmentRequest): MockReply {
    if (posted.keyConnectorKeyWrappedUserKey === "") {
      return error(HTTP_BAD_REQUEST, "key-connector-wrapped user key required");
    }

    user.keyConnectorKeyWrappedUserKey = asEncString(posted.keyConnectorKeyWrappedUserKey);
    user.masterPasswordUnlock = null;
    this.db.revisions.next();

    return {};
  }

  /**
   * Replaces a V1 account's public key encryption key pair.
   *
   * Only V1 accounts regenerate: a V2 account's public key is bound into its signed security
   * state, so it cannot be swapped out on its own.
   */
  private regenerateKeys(user: UserEntity, posted: KeyRegenerationRequest): MockReply {
    if (!("V1" in user.accountCryptographicState)) {
      return error(HTTP_BAD_REQUEST, "only a V1 account regenerates its key pair");
    }

    user.accountCryptographicState = {
      V1: { private_key: asEncString(posted.userKeyEncryptedUserPrivateKey) },
    };
    user.publicKey = posted.userPublicKey;
    this.db.revisions.next();

    return {};
  }

  private rotateUserKeys(user: UserEntity, posted: RotateUserKeysRequest): MockReply {
    const newUserKeyId = posted.newUserKeyId;
    if (newUserKeyId === undefined || !KEY_ID_PATTERN.test(newUserKeyId)) {
      return error(HTTP_BAD_REQUEST, `malformed new key id ${newUserKeyId}`);
    }

    const state = posted.wrappedAccountCryptographicState;
    const { unlockMethod, masterPasswordUnlockData } = posted.unlockMethodData;
    if (unlockMethod === "MasterPassword" && masterPasswordUnlockData === undefined) {
      return error(HTTP_BAD_REQUEST, "master password unlock data required");
    }

    user.accountCryptographicState = {
      V2: {
        private_key: asEncString(state.publicKeyEncryptionKeyPair.wrappedPrivateKey),
        signing_key: asEncString(state.signatureKeyPair.wrappedSigningKey),
        security_state: asSignedSecurityState(state.securityState.securityState),
        signed_public_key:
          state.publicKeyEncryptionKeyPair.signedPublicKey === undefined
            ? undefined
            : asSignedPublicKey(state.publicKeyEncryptionKeyPair.signedPublicKey),
      },
    };
    user.publicKey = state.publicKeyEncryptionKeyPair.publicKey;
    user.verifyingKey = state.signatureKeyPair.verifyingKey;
    user.securityVersion = state.securityState.securityVersion;
    user.userKeyId = asKeyId(newUserKeyId);

    if (masterPasswordUnlockData !== undefined) {
      user.masterPasswordUnlock = MasterPasswordUnlockDataModel.toStored(masterPasswordUnlockData);
    }

    // An upgrade token is only produced by a V1 to V2 rotation; a later rotation clears it.
    const token = posted.unlockData.v2UpgradeToken;
    if (token === undefined) {
      delete user.upgradeToken;
    } else {
      user.upgradeToken = {
        wrapped_user_key_1: asEncString(token.wrappedUserKey1),
        wrapped_user_key_2: asEncString(token.wrappedUserKey2),
      };
    }

    const now = this.db.revisions.next();
    for (const cipher of posted.accountData.ciphers ?? []) {
      const stored = this.db.ciphers.get(cipher.id);
      if (stored === undefined) {
        return error(HTTP_NOT_FOUND, `no cipher ${cipher.id} to re-encrypt`);
      }

      this.db.ciphers.update(cipher.id, {
        ...stored,
        cipher: CipherRequest.toCipher(cipher, stored.cipher, {
          id: cipher.id,
          organizationId: stored.organizationId,
          creationDate: stored.cipher.creationDate,
          revisionDate: now,
          deletedDate: stored.cipher.deletedDate ?? null,
          collectionIds: stored.cipher.collectionIds.map(asString),
        }),
      });
    }

    for (const folder of posted.accountData.folders ?? []) {
      const stored = this.db.folders.get(folder.id);
      if (stored === undefined) {
        return error(HTTP_NOT_FOUND, `no folder ${folder.id} to re-encrypt`);
      }

      this.db.folders.update(folder.id, {
        ...stored,
        folder: FolderRequest.toFolder(folder, folder.id, now),
      });
    }

    return {};
  }

  /**
   * Records the key id of an account's user key, which a backfill supplies once.
   *
   * A second attempt is refused: the id describes key material the server cannot re-read, so
   * overwriting it would leave the account pointing at a key nobody holds.
   */
  private recordUserKeyId(user: UserEntity, posted: UserKeyIdRequest): MockReply {
    if (!KEY_ID_PATTERN.test(posted.userKeyId)) {
      return error(HTTP_BAD_REQUEST, `malformed key id ${posted.userKeyId}`);
    }
    if (user.userKeyId !== undefined) {
      return error(HTTP_BAD_REQUEST, `account already has key id ${user.userKeyId}`);
    }

    user.userKeyId = asKeyId(posted.userKeyId);
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

  private createCipher(
    user: UserEntity,
    posted: CipherRequest,
    collectionIds: string[],
  ): MockReply {
    const organizationId = posted.organizationId ?? null;
    if (organizationId !== null && !this.isMember(user, organizationId)) {
      return error(HTTP_NOT_FOUND, `no organization ${organizationId} for this account`);
    }

    const id = this.db.ciphers.newId();
    const now = this.db.revisions.next();
    const cipher = CipherRequest.toCipher(posted, undefined, {
      id,
      organizationId,
      creationDate: now,
      revisionDate: now,
      deletedDate: null,
      collectionIds,
    });

    // Exactly one owner: the posting account, unless the cipher was created into an organization.
    this.db.ciphers.set(id, {
      userId: organizationId === null ? user.userId : null,
      organizationId,
      cipher,
    });

    return { json: CipherResponse.fromCipher(cipher) };
  }

  private updateCipher(user: UserEntity, id: string, posted: CipherRequest): MockReply {
    const stored = this.reachableCipher(user, id);
    if (stored === undefined) {
      return error(HTTP_NOT_FOUND, `no cipher ${id}`);
    }

    const stale = this.staleWrite(stored.cipher, posted);
    if (stale !== undefined) {
      return stale;
    }

    // Ownership is not the client's to change: an edit keeps whoever owned the cipher.
    const cipher = CipherRequest.toCipher(posted, stored.cipher, {
      id,
      organizationId: stored.organizationId,
      creationDate: stored.cipher.creationDate,
      revisionDate: this.db.revisions.next(),
      deletedDate: stored.cipher.deletedDate ?? null,
      collectionIds: stored.cipher.collectionIds.map(asString),
    });

    this.db.ciphers.update(id, { ...stored, cipher });
    return { json: CipherResponse.fromCipher(cipher) };
  }

  private deleteCipher(user: UserEntity, id: string): MockReply {
    if (this.reachableCipher(user, id) === undefined) {
      return error(HTTP_NOT_FOUND, `no cipher ${id}`);
    }

    this.db.ciphers.remove(id);
    return {};
  }

  /** Sets or clears a cipher's `deletedDate` and bumps its revision. */
  private restamp(user: UserEntity, id: string, deletedDate: string | null): MockReply {
    const stored = this.reachableCipher(user, id);
    if (stored === undefined) {
      return error(HTTP_NOT_FOUND, `no cipher ${id}`);
    }

    const cipher: Cipher = {
      ...stored.cipher,
      deletedDate: deletedDate ?? undefined,
      revisionDate: this.db.revisions.next(),
    };
    this.db.ciphers.update(id, { ...stored, cipher });

    return { json: CipherResponse.fromCipher(cipher) };
  }

  private createFolder(user: UserEntity, posted: FolderRequest): MockReply {
    const id = this.db.folders.newId();
    const folder = FolderRequest.toFolder(posted, id, this.db.revisions.next());

    this.db.folders.set(id, { userId: user.userId, folder });
    return { json: FolderResponse.fromFolder(folder) };
  }

  private updateFolder(user: UserEntity, id: string, posted: FolderRequest): MockReply {
    const stored = this.db.folders.get(id);
    if (stored === undefined || stored.userId !== user.userId) {
      return error(HTTP_NOT_FOUND, `no folder ${id}`);
    }

    const folder = FolderRequest.toFolder(posted, id, this.db.revisions.next());
    this.db.folders.update(id, { ...stored, folder });

    return { json: FolderResponse.fromFolder(folder) };
  }

  /** Whether `user` is a member of `organizationId`. */
  private isMember(user: UserEntity, organizationId: string): boolean {
    const organization = this.db.organizations.get(organizationId);

    return organization?.members.some((member) => member.userId === user.userId) === true;
  }
}
