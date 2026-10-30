import type { DecryptCipherResult } from "@bitwarden/sdk-internal";

import type { SeedAccount, SeedVault } from "../server-emulator/server-emulator";

import type { ClientEmulator } from "./client-emulator";

export const IGNORED_FIELDS = ["revisionDate", "creationDate"] as const;

/**
 * Fields where `false` means the same as an absent value. The blob format stores an unset
 * `httpAuthenticationEnabled` as `false` while the legacy format leaves it unset, so a cipher that
 * changes format (for example during key rotation) changes its representation, not its meaning.
 */
const FALSE_MEANS_ABSENT_FIELDS: readonly string[] = ["httpAuthenticationEnabled"];

/**
 * Fields where an empty list means the same as an absent value. An item with no custom fields
 * decrypts with `fields: []` before a key rotation and with no `fields` after one against a real
 * server: again a change of representation, not of meaning.
 */
const EMPTY_MEANS_ABSENT_FIELDS: readonly string[] = ["fields"];

/**
 * Decrypts everything an unlocked client's repositories hold, comparing to the plaintext `seed`
 * records. Throws on the first difference.
 *
 * `ignore` names the fields to drop before comparing, and defaults to {@link IGNORED_FIELDS}.
 * A test that has written nothing can pass `[]` to hold the account to every field it started with.
 *
 * Only the recorded vault is read, so `seed` is a whole {@link SeedAccount} for a seeded account
 * and just the vault for a live one, whose plaintext is captured rather than committed.
 */
export async function validateVault(
  client: ClientEmulator,
  seed: { vault?: SeedVault },
  ignore: readonly string[] = IGNORED_FIELDS,
): Promise<void> {
  const sdk = client.getPasswordManagerClient();

  // 1. Compare the vault items, which have to decrypt before they can be compared at all
  validateCiphers(await sdk.vault().ciphers().get_all(), seed, ignore);

  // 2. Compare the folders
  const folders = await sdk.vault().folders().list();
  for (const folder of folders) {
    const id = String(folder.id);
    const recorded = (seed.vault?.folders ?? []).find((item) => item.id === id)?.decrypted;
    if (recorded === undefined) {
      throw new Error(`local state holds folder ${id}, which the vector does not record`);
    }

    expectPlaintextEqual(folder, recorded, `folder ${id}`, ignore);
  }
}

/**
 * Compares decrypted ciphers to the plaintext `seed` records. Throws on a cipher that failed to
 * decrypt, or one the vector does not record.
 */
export function validateCiphers(
  result: DecryptCipherResult,
  seed: { vault?: SeedVault },
  ignore: readonly string[] = IGNORED_FIELDS,
): void {
  if (result.failures.length > 0) {
    const ids = result.failures.map((cipher) => String(cipher.id)).join(", ");
    throw new Error(`${result.failures.length} cipher(s) failed to decrypt: ${ids}`);
  }

  for (const cipher of result.successes) {
    const id = String(cipher.id);
    const recorded = (seed.vault?.ciphers ?? []).find((item) => item.id === id)?.decrypted;
    if (recorded === undefined) {
      throw new Error(`decrypted cipher ${id}, which the vector does not record`);
    }

    expectPlaintextEqual(cipher, recorded, `cipher ${id}`, ignore);
  }
}

/** Compares two decrypted values after normalizing them */
export function expectPlaintextEqual(
  actual: unknown,
  expected: unknown,
  label: string,
  ignore: readonly string[] = IGNORED_FIELDS,
): void {
  expect({ label, value: normalize(actual, ignore) }).toEqual({
    label,
    value: normalize(expected, ignore),
  });
}

/**
 * Drops absent fields, `ignore`d keys, {@link FALSE_MEANS_ABSENT_FIELDS} set to `false` and
 * {@link EMPTY_MEANS_ABSENT_FIELDS} set to an empty list, at every depth.
 *
 * serde_json converts a Rust `None` to `null` while serde_wasm_bindgen converts it to `undefined`,
 * so a raw comparison fails on every optional field while proving nothing.
 */
export function normalize(value: unknown, ignore: readonly string[]): unknown {
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
    if (entry === undefined) {
      continue;
    }

    if (entry === false && FALSE_MEANS_ABSENT_FIELDS.includes(key)) {
      continue;
    }

    if (Array.isArray(entry) && entry.length === 0 && EMPTY_MEANS_ABSENT_FIELDS.includes(key)) {
      continue;
    }

    normalized[key] = entry;
  }

  return normalized;
}
