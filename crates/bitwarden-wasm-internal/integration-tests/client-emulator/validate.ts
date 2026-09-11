// Proving an account still decrypts to what it is defined to decrypt to.
//
// The validator opens whatever local state holds and compares the plaintext to the vector's record.
// It never decrypts the vector's own ciphertext with the vector's own keys and calls that a pass:
// that would only prove the test data is self-consistent.

import type { CipherView, FolderView, InitUserCryptoMethod } from "@bitwarden/sdk-internal";

import type { SeedAccount } from "../server-emulator/server-emulator";

import type { LocalState } from "./local-state";

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
 * The comparison runs both ways: an item local state holds that the vector does not record is a
 * failure, and so is a recorded item that never arrived. One direction alone would pass a sync that
 * delivered a single cipher out of five.
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

  assertNothingMissing(expected.ciphers, ciphers, "cipher");
  assertNothingMissing(expected.folders, folders, "folder");

  return { ciphers: ciphers.length, folders: folders.length };
}

/** Throws when an item the vector records never reached local state. */
function assertNothingMissing(
  expected: Record<string, unknown>,
  present: { id?: unknown }[],
  label: string,
): void {
  const arrived = new Set(present.map((item) => String(item.id)));
  const missing = Object.keys(expected).filter((id) => !arrived.has(id));

  if (missing.length > 0) {
    throw new Error(`local state is missing ${missing.length} ${label}(s): ${missing.join(", ")}`);
  }
}

/**
 * Compares two decrypted values after normalizing away the differences that are not real.
 *
 * Guards against an `ignore` list that has grown until nothing is left to compare. An assertion that
 * excuses every field it was meant to check passes against anything, which is worse than no
 * assertion at all because it looks like coverage.
 */
export function expectPlaintextEqual(
  actual: unknown,
  expected: unknown,
  label: string,
  ignore: readonly string[] = SERVER_OWNED_FIELDS,
): void {
  assertSomethingLeftToCompare(expected, ignore, label);

  expect({ label, value: normalize(actual, ignore) }).toEqual({
    label,
    value: normalize(expected, ignore),
  });
}

/**
 * Throws when `ignore` covers every field `expected` actually carries.
 *
 * Checked against the raw value rather than the normalized one, so it still holds if `normalize`
 * itself is what went wrong.
 */
function assertSomethingLeftToCompare(
  expected: unknown,
  ignore: readonly string[],
  label: string,
): void {
  if (expected === null || typeof expected !== "object" || Array.isArray(expected)) {
    return;
  }

  const present = Object.entries(expected as Record<string, unknown>).filter(
    ([, value]) => value !== null && value !== undefined,
  );
  if (present.length === 0) {
    return;
  }

  if (present.every(([key]) => ignore.includes(key))) {
    throw new Error(`${label}: every field present is ignored, so this comparison proves nothing`);
  }
}

/**
 * Drops absent fields and `ignore`d keys at every depth.
 *
 * serde_json renders a Rust `None` as `null` while serde_wasm_bindgen renders it as `undefined`, so
 * a raw comparison fails on every optional field while proving nothing. Dropping is recursive
 * because a nested `revisionDate` is as server-owned as a top-level one.
 *
 * `inAttachments` scopes one exclusion. An `AttachmentView` carries `decryptedKey` — the attachment
 * key in the clear — which a vector deliberately does not record, because a vector is committed to
 * git. The scope matters: `decryptedKey` is also the variant tag of `InitUserCryptoMethod`, and
 * dropping that would erase whole unlock methods.
 */
function normalize(value: unknown, ignore: readonly string[], inAttachments = false): unknown {
  if (value === null || value === undefined) {
    return undefined;
  }

  if (Array.isArray(value)) {
    return value.map((entry) => normalize(entry, ignore, inAttachments));
  }

  if (typeof value !== "object") {
    return value;
  }

  const normalized: Record<string, unknown> = {};
  for (const key of Object.keys(value as Record<string, unknown>).sort()) {
    if (ignore.includes(key)) {
      continue;
    }
    if (inAttachments && key === "decryptedKey") {
      continue;
    }

    const entry = normalize(
      (value as Record<string, unknown>)[key],
      ignore,
      inAttachments || key === "attachments",
    );
    if (entry !== undefined) {
      normalized[key] = entry;
    }
  }

  return normalized;
}
