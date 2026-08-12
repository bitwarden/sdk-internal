// The two helpers every test uses: pull a server down into local state, and validate local state
// against the committed test data.
//
// These exist so tests stop restating "the account is still coherent". Before, each suite hand-wrote its
// own re-unlock-decrypt-compare block and they had drifted on how thoroughly they looked and which
// fields they excused.
//
// The validator deliberately takes no `ApiServer`: it validates *local state* against *test data*. That
// local state agrees with the server is established by `syncToLocalState` having overwritten it from the
// server immediately beforehand — so a test that syncs and then validates has asserted both.

import type { CipherView, Folder, FolderView, InitUserCryptoMethod } from "@bitwarden/sdk-internal";

import type { CipherVectorItem, UserVector, VectorItem } from "../test-vectors/load";
import {
  expectJsonEqual,
  expectPlaintextEqual,
  SERVER_OWNED_FIELDS,
  validateUserKey,
} from "../test-vectors/validate";

import type { ApiServer } from "./api-server";
import { LocalState } from "./local-state";

/**
 * Fields excused by default when comparing a decrypted view to recorded plaintext.
 *
 * `revisionDate` is stamped by the server on every write. `key` is a pass-through of the *still-wrapped*
 * cipher key, so it necessarily changes whenever the cipher is re-encrypted — most visibly on every key
 * rotation.
 */
export const VOLATILE_VIEW_FIELDS = [...SERVER_OWNED_FIELDS, "key"] as const;

/**
 * Copies an account out of the server and into local state, keys and vault alike.
 *
 * This is the sync a real client performs after any write, and it is the operation that makes a mutation
 * observable: local state is *replaced* by what the server holds rather than trusted to already be
 * right. Running it twice must leave local state byte-identical.
 */
export async function syncToLocalState(
  api: ApiServer,
  email: string,
  local: LocalState,
): Promise<void> {
  const user = api.db.userByEmail(email);

  await local.seedAccount({
    userId: user.userId,
    email: user.email,
    accountCryptographicState: user.accountCryptographicState,
    kdf: user.kdf,
    masterPasswordUnlock: user.masterPasswordUnlock,
    upgradeToken: user.credentials.upgradeToken,
    organizationKeys: user.credentials.organizationKeys,
  });

  await local.seedVault({
    ciphers: api.db.ciphersFor(user.userId),
    folders: api.db.foldersFor(user.userId),
  });
}

/**
 * The unlock method for an account in local state.
 *
 * Master password when the account has one, because that is the path a returning client takes and the
 * one whose data a rotation refreshes. Otherwise the account's own method, rebuilt from whatever the
 * server currently holds so a rotated account is opened with its *new* unlock data rather than the
 * seeded copy.
 */
export function unlockMethodFor(api: ApiServer, email: string): InitUserCryptoMethod {
  const user = api.db.userByEmail(email);
  if (user.masterPasswordUnlock === null) {
    // A key-connector account: the connector key itself never changes, but the user key it wraps does,
    // so the wrapping is taken from the account and the key from the seeded credentials.
    if (user.keyConnectorKeyWrappedUserKey !== undefined) {
      const seeded = user.credentials.unlockMethods.find((method) => "keyConnector" in method) as
        Extract<InitUserCryptoMethod, { keyConnector: unknown }> | undefined;
      if (seeded !== undefined) {
        return {
          keyConnector: {
            master_key: seeded.keyConnector.master_key,
            user_key: user.keyConnectorKeyWrappedUserKey,
          },
        } as never;
      }
    }
    return user.credentials.unlockMethods[0];
  }
  return {
    masterPasswordUnlock: {
      password: user.credentials.password,
      master_password_unlock: {
        masterKeyWrappedUserKey: user.masterPasswordUnlock.masterKeyWrappedUserKey,
        salt: user.masterPasswordUnlock.salt,
        kdf: user.masterPasswordUnlock.kdf,
      },
    },
  } as never;
}

export interface ValidationResult {
  ciphers: number;
  folders: number;
}

/** Per-item plaintext the act step deliberately changed, merged over the recorded view. */
export interface ExpectedOverrides {
  ciphers?: Record<string, Partial<CipherView>>;
  folders?: Record<string, Partial<FolderView>>;
}

export interface ValidateOptions {
  ignore?: readonly string[];
  expect?: ExpectedOverrides;
  /** Assert the unlocked client holds this user key. */
  expectedUserKey?: string;
  /** Its COSE key id, or `null` for a V1 key that carries none. */
  expectedUserKeyId?: string | null;
}

/**
 * Unlocks a client on `local` and decrypts **everything the repositories hold**, comparing each item to
 * the plaintext the test data records.
 *
 * Decrypting what local state holds — rather than the test data's own copies — is the whole point. After
 * a write those are re-encrypted ciphertexts, so this is what shows the write produced something a
 * client can still open.
 *
 * Item-shaped so an organization vector works as well as a user one.
 */
export async function validateLocalState(
  local: LocalState,
  method: InitUserCryptoMethod,
  expected: {
    ciphers?: CipherVectorItem[];
    folders?: VectorItem<Folder, FolderView>[];
  },
  options: ValidateOptions = {},
): Promise<ValidationResult> {
  const ignore = options.ignore ?? VOLATILE_VIEW_FIELDS;
  const client = await local.unlock(method);

  if (options.expectedUserKey !== undefined) {
    await validateUserKey(client, options.expectedUserKey, options.expectedUserKeyId);
  }

  const ciphersClient = client.vault().ciphers();
  for (const item of expected.ciphers ?? []) {
    const stored = await local.ciphers.get(item.id);
    if (stored === null) {
      throw new Error(`cipher ${item.id} is not in local state`);
    }
    expectPlaintextEqual(
      await ciphersClient.decrypt(stored),
      { ...item.decrypted, ...(options.expect?.ciphers?.[item.id] ?? {}) },
      `cipher ${item.id}`,
      ignore,
    );
  }

  const foldersClient = client.vault().folders();
  for (const item of expected.folders ?? []) {
    const stored = await local.folders.get(item.id);
    if (stored === null) {
      throw new Error(`folder ${item.id} is not in local state`);
    }
    expectPlaintextEqual(
      foldersClient.decrypt(stored),
      { ...item.decrypted, ...(options.expect?.folders?.[item.id] ?? {}) },
      `folder ${item.id}`,
      ignore,
    );
  }

  return {
    ciphers: (expected.ciphers ?? []).length,
    folders: (expected.folders ?? []).length,
  };
}

/**
 * Re-unlocks from the server and asserts the cipher with `id` decrypts to `expected`.
 *
 * This is the honest read of a single item after a write. The value `create` or `edit` returned came out
 * of the response the writing client was already holding; this one comes back through storage, decrypted
 * by a client that knows nothing except what the server had.
 *
 * `notInCiphertext` additionally asserts that none of those strings appear anywhere in the *stored*
 * cipher — the plaintext check that a "the item round-tripped" assertion cannot make on its own, since a
 * server that stored everything in the clear would round-trip perfectly.
 */
export async function expectCipherFromServer(
  api: ApiServer,
  email: string,
  id: string,
  expected: CipherView,
  label: string,
  options: { notInCiphertext?: readonly string[] } = {},
): Promise<void> {
  const local = new LocalState();
  await syncToLocalState(api, email, local);

  const stored = await local.ciphers.get(id);
  if (stored === null) {
    throw new Error(`${label}: cipher ${id} is not on the server`);
  }
  for (const plaintext of options.notInCiphertext ?? []) {
    expect(JSON.stringify(stored)).not.toContain(plaintext);
  }

  const client = await local.unlock(unlockMethodFor(api, email));
  expectJsonEqual(await client.vault().ciphers().get(id), expected, label);
}

/**
 * Lock, then unlock: the local state a client already holds must still open.
 *
 * Deliberately does **not** sync. That is why it exists separately — it is the only assertion that
 * catches a write which posted a correct account to the server but left the writing client's own
 * storage wrong. Validating only after a sync would overwrite the very thing that needs checking.
 *
 * It unlocks a *new* client on the *same* local state, which is what a lock/unlock cycle is: the keys
 * leave memory while the bridge and the repositories stay.
 */
export async function validateAfterLockUnlock(
  local: LocalState,
  method: InitUserCryptoMethod,
  vector: UserVector,
  options: ValidateOptions = {},
): Promise<ValidationResult> {
  return validateVector(local, method, vector, options);
}

/**
 * Log out, then log back in: discard local state entirely, sync from the server, and unlock.
 *
 * Nothing carries over — new bridge, new repositories, new client — so this asserts the *server* holds
 * everything a returning client needs. Returns the fresh local state for any follow-up inspection.
 */
export async function validateAfterLogoutLogin(
  api: ApiServer,
  email: string,
  vector: UserVector,
  options: ValidateOptions = {},
): Promise<LocalState> {
  const fresh = new LocalState();
  await syncToLocalState(api, email, fresh);
  await validateVector(fresh, unlockMethodFor(api, email), vector, options);
  return fresh;
}

/**
 * The common case: validate everything a `UserVector` declares, and its key material.
 *
 * This is what a test's whole assert section is normally reduced to.
 */
export async function validateVector(
  local: LocalState,
  method: InitUserCryptoMethod,
  vector: UserVector,
  options: ValidateOptions = {},
): Promise<ValidationResult> {
  const result = await validateLocalState(
    local,
    method,
    { ciphers: vector.vault.ciphers, folders: vector.vault.folders },
    {
      // Key material is checked unless the caller says otherwise — a rotation changes it, and says so.
      expectedUserKey: vector.rawCryptographicState.userKey,
      expectedUserKeyId: vector.rawCryptographicState.userKeyId,
      ...options,
    },
  );

  // Guards against a vector with an empty vault making the whole call vacuous.
  expect(result.ciphers).toBeGreaterThan(0);
  return result;
}
