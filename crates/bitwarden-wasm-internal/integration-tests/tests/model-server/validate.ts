// Bringing an account out of the model server and proving it still works.
//
// The validators decrypt whatever local state holds and compare it to the recorded plaintext. They
// never decrypt the account's own recorded ciphertext: after a write that has been re-encrypted, and
// checking it would only prove the test data is self-consistent.

import type { CipherView, FolderView, InitUserCryptoMethod } from "@bitwarden/sdk-internal";

import type { ApiServer, SeedAccount } from "./api-server";
import { LocalState, type LocalAccount } from "./local-state";

/** Fields the server stamps, which a client cannot be expected to reproduce. */
export const SERVER_OWNED_FIELDS = ["revisionDate", "creationDate"] as const;

export interface ValidationResult {
  ciphers: number;
  folders: number;
}

/** Per-item overrides for what an act step deliberately changed. */
export interface ExpectedOverrides {
  ciphers?: Record<string, Partial<CipherView>>;
  folders?: Record<string, Partial<FolderView>>;
}

export interface ValidateOptions {
  /** Field names to drop before comparing, at every depth. Defaults to {@link SERVER_OWNED_FIELDS}. */
  ignore?: readonly string[];
  /** What the test changed on purpose, merged over the recorded plaintext. */
  expect?: ExpectedOverrides;
}

/** The plaintext a vector records, keyed by item id. */
export interface ExpectedVault {
  ciphers: Record<string, CipherView>;
  folders: Record<string, FolderView>;
}

/**
 * Copies an account out of the server into local state, exactly as a sync does: keys into the state
 * bridge, vault into the repositories.
 *
 * Idempotent — running it twice must leave the same state, or a test that syncs before and after a
 * write is measuring the sync rather than the write.
 */
export async function syncToLocalState(
  api: ApiServer,
  email: string,
  local: LocalState,
): Promise<void> {
  const user = api.db.userByEmail(email);

  const account: LocalAccount = {
    userId: user.userId,
    email: user.email,
    accountCryptographicState: user.accountCryptographicState,
    kdf: user.kdf,
    ...(user.masterPasswordUnlock === null
      ? {}
      : {
          masterPasswordUnlock: {
            masterKeyWrappedUserKey: user.masterPasswordUnlock.masterKeyWrappedUserKey,
            salt: user.masterPasswordUnlock.salt,
            kdf: user.masterPasswordUnlock.kdf,
          },
        }),
    ...(user.credentials.upgradeToken === undefined
      ? {}
      : { upgradeToken: user.credentials.upgradeToken }),
    organizationKeys: user.credentials.organizationKeys,
  };

  await local.seedAccount(account);
  await local.seedVault({
    ciphers: api.db.ciphers.for(user.userId),
    folders: api.db.folders.for(user.userId),
  });
}

/**
 * How to unlock the account the server currently holds.
 *
 * Master password is preferred, and is re-read from the server rather than from the vector, so an
 * operation that rewrote the unlock data is exercised rather than bypassed.
 */
export function unlockMethodFor(api: ApiServer, email: string): InitUserCryptoMethod {
  const user = api.db.userByEmail(email);

  if (user.masterPasswordUnlock !== null) {
    return {
      masterPasswordUnlock: {
        password: user.credentials.password,
        master_password_unlock: {
          masterKeyWrappedUserKey: user.masterPasswordUnlock.masterKeyWrappedUserKey,
          salt: user.masterPasswordUnlock.salt,
          kdf: user.masterPasswordUnlock.kdf,
        },
      },
    };
  }

  const [method] = user.credentials.unlockMethods;
  if (method === undefined) {
    throw new Error(`account ${email} declares no unlock method`);
  }
  return method;
}

/** The plaintext a seed account records, keyed by id. */
export function expectedVaultOf(vector: SeedAccount): ExpectedVault {
  const ciphers: Record<string, CipherView> = {};
  const folders: Record<string, FolderView> = {};

  for (const item of vector.vault?.ciphers ?? []) {
    if (item.decrypted !== undefined) {
      ciphers[item.id] = item.decrypted;
    }
  }
  for (const item of vector.vault?.folders ?? []) {
    if (item.decrypted !== undefined) {
      folders[item.id] = item.decrypted;
    }
  }

  return { ciphers, folders };
}

/**
 * Unlocks `local` and decrypts everything its repositories hold, comparing to `expected`.
 *
 * Asserts a non-zero item count: a validator that silently found nothing to check reports success
 * for an account whose vault failed to load at all.
 */
export async function validateLocalState(
  local: LocalState,
  method: InitUserCryptoMethod,
  expected: ExpectedVault,
  options: ValidateOptions = {},
): Promise<ValidationResult> {
  const client = await local.unlock(method);
  const ignore = options.ignore ?? SERVER_OWNED_FIELDS;

  const ciphers = local.ciphers.dump();
  for (const cipher of ciphers) {
    const id = String(cipher.id);
    const recorded = expected.ciphers[id];
    if (recorded === undefined) {
      throw new Error(`local state holds cipher ${id}, which the vector does not record`);
    }

    const view = await client.vault().ciphers().decrypt(cipher);
    expectPlaintextEqual(
      view,
      { ...recorded, ...options.expect?.ciphers?.[id] },
      `cipher ${id}`,
      ignore,
    );
  }

  const folders = local.folders.dump();
  for (const folder of folders) {
    const id = String(folder.id);
    const recorded = expected.folders[id];
    if (recorded === undefined) {
      throw new Error(`local state holds folder ${id}, which the vector does not record`);
    }

    const view = await client.vault().folders().decrypt(folder);
    expectPlaintextEqual(
      view,
      { ...recorded, ...options.expect?.folders?.[id] },
      `folder ${id}`,
      ignore,
    );
  }

  if (ciphers.length + folders.length === 0) {
    throw new Error("nothing to validate: local state holds no ciphers and no folders");
  }

  return { ciphers: ciphers.length, folders: folders.length };
}

/**
 * Locks and reopens the client that performed a write, without syncing.
 *
 * This has to run before anything that syncs, because a sync overwrites the local state it checks. A
 * write that posts a correct account but fails to persist locally is invisible to a sync-first
 * assertion, and that case is the whole reason the two helpers are separate.
 */
export async function validateAfterLockUnlock(
  local: LocalState,
  method: InitUserCryptoMethod,
  expected: ExpectedVault,
  options: ValidateOptions = {},
): Promise<ValidationResult> {
  await local.clearEphemeral();
  return await validateLocalState(local, method, expected, options);
}

/**
 * Discards local state entirely, syncs from the server and unlocks from nothing else.
 *
 * The client that performed the write is not evidence on its own — it holds values from its own
 * response — so this proves a returning client is given a working account.
 */
export async function validateAfterLogoutLogin(
  api: ApiServer,
  email: string,
  expected: ExpectedVault,
  options: ValidateOptions = {},
): Promise<LocalState> {
  const fresh = new LocalState();
  await syncToLocalState(api, email, fresh);
  await validateLocalState(fresh, unlockMethodFor(api, email), expected, options);
  return fresh;
}

/** Compares two decrypted values after normalizing away the differences that are not real. */
export function expectPlaintextEqual(
  actual: unknown,
  expected: unknown,
  label: string,
  ignore: readonly string[] = SERVER_OWNED_FIELDS,
): void {
  expect({ label, value: normalize(actual, ignore) }).toEqual({
    label,
    value: normalize(expected, ignore),
  });
}

/**
 * Drops absent fields and `ignore`d keys at every depth, and sorts object keys.
 *
 * serde_json renders a Rust `None` as `null` while serde_wasm_bindgen renders it as `undefined`, so
 * a raw comparison fails on every optional field while proving nothing. Dropping is recursive
 * because a nested `revisionDate` is as server-owned as a top-level one.
 */
function normalize(value: unknown, ignore: readonly string[]): unknown {
  if (value === null || value === undefined) {
    return undefined;
  }

  if (Array.isArray(value)) {
    return value.map((entry) => normalize(entry, ignore));
  }

  if (typeof value !== "object") {
    return value;
  }

  const normalized: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    if (ignore.includes(key)) {
      continue;
    }
    const entry = normalize((value as Record<string, unknown>)[key], ignore);
    if (entry !== undefined) {
      normalized[key] = entry;
    }
  }
  return normalized;
}
