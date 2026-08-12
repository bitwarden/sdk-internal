// Shared scaffolding for the vault suites: the model-server harness the CRUD tests run on, the
// vector-only unlock the encryption matrix uses, and the case tables both are driven by.
//
// The CRUD suites all want the same four things — a seeded account, the servers installed, local state
// synced down from them, and an unlocked client — plus the same two-directional "is the account still
// usable" assertion afterwards. That is `arrangeVault`.

import type {
  CipherView,
  CipherViewType,
  FeatureFlags,
  InitUserCryptoMethod,
  PasswordManagerClient,
} from "@bitwarden/sdk-internal";

import { ApiServer } from "../model-server/api-server";
import { installServers, type InstalledServers } from "../model-server/install";
import { LocalState } from "../model-server/local-state";
import {
  syncToLocalState,
  unlockMethodFor,
  validateAfterLockUnlock,
  validateAfterLogoutLogin,
  type ValidateOptions,
} from "../model-server/sync";
import {
  loadUserVectors,
  userVector,
  type CipherVectorItem,
  type UserVector,
} from "../test-vectors/load";
import { makePasswordManagerClient, makeStateBridge } from "../utils";

/** `v1-pbkdf2-password` unlocks at 600k PBKDF2 rounds, and each case unlocks at least once. */
export const VAULT_TIMEOUT = 180_000;

export const users = loadUserVectors();

/** Every vector, shaped for `describe.each`. */
export const vectorCases = users.map((vector) => [vector.name, vector] as const);

/**
 * `v1-pbkdf2-password` carries five of the seven distinct cipher shapes on its own — keyless, keyed, and
 * one cipher each for V0, V1 and V2 attachments. `v2-argon2id-blob` supplies the two blob shapes.
 */
export const EDIT_MATRIX_VECTORS = ["v1-pbkdf2-password", "v2-argon2id-blob"] as const;

/** A vector with folders in its vault, and a cheap KDF. */
export const FOLDER_VECTOR = userVector(users, "v1-argon2id-password");

export const FILE_CONTENTS = new TextEncoder().encode("attachment contents, 1234567890, éèê");

// ---- the model-server harness -------------------------------------------------------------------

export interface VaultHarness {
  api: ApiServer;
  servers: InstalledServers;
  local: LocalState;
  vector: UserVector;
  client: PasswordManagerClient;
  /** The `afterEach` assertions: nothing unmatched, and no secret on the wire. */
  assertClean(): void;
  /**
   * Asserts the write left the account usable, from both directions a real client can arrive from.
   *
   * The lock/unlock half comes first and on purpose: it reads the writing client's *own* local state
   * before anything overwrites it, which is the only way to catch a write that posted a correct account
   * but corrupted local storage.
   */
  assertAccountIntact(options?: ValidateOptions): Promise<void>;
}

/** Seeds the account, installs the servers, syncs it into fresh local state, and unlocks. */
export async function arrangeVault(vector: UserVector): Promise<VaultHarness> {
  const api = new ApiServer();
  api.seedUser(vector);
  const servers = installServers({ api });
  const local = new LocalState();
  await syncToLocalState(api, vector.account.email, local);
  const client = await local.unlock(unlockMethodFor(api, vector.account.email));

  return {
    api,
    servers,
    local,
    vector,
    client,
    assertClean() {
      expect(servers.unmatched.map((request) => request.route)).toEqual([]);
      // No seeded account's password, user key, private key or master key may ever appear in a request
      // body. Policed by the server on every request, so no individual test has to remember to look.
      expect(api.secretLeaks()).toEqual([]);
      servers.restore();
    },
    async assertAccountIntact(options: ValidateOptions = {}) {
      const email = vector.account.email;
      await validateAfterLockUnlock(local, unlockMethodFor(api, email), vector, options);
      await validateAfterLogoutLogin(api, email, vector, options);
    },
  };
}

// ---- the vector-only unlock the encryption matrix uses -------------------------------------------

/**
 * Unlocks a vector with its first declared unlock method, with no server involved.
 *
 * Which method is used does not affect encryption — they all arrive at the same user key — so the
 * encryption matrix does not iterate over them, and stays cheap.
 */
export async function unlockForEncryption(
  vector: UserVector,
  flags?: FeatureFlags,
): Promise<PasswordManagerClient> {
  const client = makePasswordManagerClient(makeStateBridge());
  if (flags !== undefined) {
    await client.platform().load_flags(flags);
  }
  await client.crypto().initialize_user_crypto({
    userId: vector.account.userId,
    kdfParams: vector.account.kdf,
    email: vector.account.email,
    accountCryptographicState: vector.account.accountCryptographicState,
    method: vector.unlockMethods[0] as InitUserCryptoMethod,
    upgradeToken: vector.account.upgradeToken,
  });
  return client;
}

export const featureFlags = (entries: Record<string, boolean>) =>
  new Map(Object.entries(entries)) as FeatureFlags;

// ---- cipher shape helpers -----------------------------------------------------------------------

/** Describes a cipher variant, for readable test names. */
export function variantOf(item: CipherVectorItem): string {
  const attachments = Object.values(item.keys.attachments).map((a) => a.version);
  const shape = item.blobEncrypted
    ? "blob"
    : item.keys.cipherKey !== null
      ? "legacy keyed"
      : "legacy keyless";
  return `${shape}, ${attachments.length === 0 ? "no attachments" : `${attachments.join("+")} attachment`}`;
}

/** Rebuilds the `CipherViewType` an edit request needs from a decrypted view. */
export function cipherViewType(view: CipherView): CipherViewType {
  if (view.login) return { login: view.login! };
  if (view.card) return { card: view.card! };
  if (view.identity) return { identity: view.identity! };
  if (view.secureNote) return { secureNote: view.secureNote! };
  if (view.sshKey) return { sshKey: view.sshKey! };
  if (view.bankAccount) return { bankAccount: view.bankAccount! };
  if (view.passport) return { passport: view.passport! };
  if (view.driversLicense) return { driversLicense: view.driversLicense! };
  throw new Error(`cipher ${view.id} has no recognised type payload`);
}

/**
 * How an edit leaves `fields` and `passwordHistory`, which differs by encryption mode.
 *
 * On the **legacy** path they come back as empty collections rather than absent:
 * `convert_request_to_cipher_view` assigns `fields: Some(r.fields)` and `update_password_history`
 * always assigns `Some(..)`. On the **blob** path they survive as absent, because the whole view is
 * resealed rather than mapped field by field.
 *
 * Stated as expected values rather than added to the ignore list, so a genuine change to either still
 * fails — and so the difference between the two modes is recorded rather than blurred.
 */
export function normalisedByEdit(before: CipherView, item: CipherVectorItem): Partial<CipherView> {
  if (item.blobEncrypted) {
    return {};
  }
  return {
    fields: before.fields ?? [],
    passwordHistory: before.passwordHistory ?? [],
  };
}

/** An edit request that changes `name`, carrying everything else through unchanged. */
export function renameRequest(view: CipherView, name: string) {
  return {
    id: view.id!,
    organizationId: view.organizationId ?? undefined,
    folderId: view.folderId ?? undefined,
    favorite: view.favorite,
    reprompt: view.reprompt,
    name,
    notes: view.notes ?? undefined,
    fields: view.fields ?? [],
    type: cipherViewType(view),
    revisionDate: view.revisionDate,
    archivedDate: view.archivedDate ?? undefined,
    // Carried through unchanged: an edit must not disturb attachment keys.
    attachments: view.attachments ?? [],
    key: view.key ?? undefined,
  };
}

// ---- attachment case table ----------------------------------------------------------------------

/**
 * Every (vector, cipher, attachment) triple in the set that actually has an attachment.
 *
 * `v1-pbkdf2-password` is the only account carrying a V0 and a V1 attachment; the V2 ones are elsewhere.
 */
export const attachmentCases = EDIT_MATRIX_VECTORS.flatMap((name) => {
  const vector = userVector(users, name);
  return vector.vault.ciphers.flatMap((item) =>
    Object.entries(item.keys.attachments).map(
      ([attachmentId, keys]) =>
        [
          `${keys.version} attachment on a ${item.keys.cipherKey === null ? "keyless" : "keyed"}${item.blobEncrypted ? " blob" : ""} cipher`,
          vector,
          item,
          attachmentId,
          keys,
        ] as const,
    ),
  );
});
