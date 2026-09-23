import type { SeedVault } from "../server-emulator/server-emulator";

import type { ClientEmulator } from "./client-emulator";

export const IGNORED_FIELDS = ["revisionDate", "creationDate"] as const;

/**
 * An `AttachmentView` carries the attachment key in the clear, which a vector deliberately does not
 * record, because a vector is committed to git.
 */
const ATTACHMENT_KEY_FIELD = "decryptedKey";

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
  const { successes: ciphers, failures } = await sdk.vault().ciphers().get_all();
  if (failures.length > 0) {
    const ids = failures.map((cipher) => String(cipher.id)).join(", ");
    throw new Error(`${failures.length} cipher(s) failed to decrypt: ${ids}`);
  }

  for (const cipher of ciphers) {
    const id = String(cipher.id);
    const recorded = (seed.vault?.ciphers ?? []).find((item) => item.id === id)?.decrypted;
    if (recorded === undefined) {
      throw new Error(`local state holds cipher ${id}, which the vector does not record`);
    }

    expectPlaintextEqual(cipher, recorded, `cipher ${id}`, [...ignore, ATTACHMENT_KEY_FIELD]);
  }

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
 * Drops absent fields and `ignore`d keys at every depth.
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
    if (entry !== undefined) {
      normalized[key] = entry;
    }
  }

  return normalized;
}
