// Asserts that an unlocked client decrypts a test vector to the state the vector recorded.
//
// The comparison is on the JSON wire form rather than field by field, matching what
// `VaultVector::validate_decrypted` does on the Rust side, so the two languages cannot disagree about
// what "equal" means.

import { CryptoClient, type PasswordManagerClient } from "@bitwarden/sdk-internal";

import type { UserVector } from "./load";

/**
 * Sends are deliberately not validated here.
 *
 * `SendClient` exposes no pure `decrypt(send)` — a send can only be reached through
 * `get`/`list`, which read from registered state repositories that this suite does not wire up. Sends
 * are therefore covered on the Rust side by `VaultVector::validate_decrypted`. This constant exists so
 * the gap is visible in the code rather than being a silent omission.
 */
export const SENDS_VALIDATED_IN_RUST_ONLY = true;

/** What was actually checked, so a test can assert the validation was not vacuous. */
export interface ValidationSummary {
  ciphers: number;
  folders: number;
  sendsSkipped: number;
}

/**
 * Decrypts every cipher and folder in `vector` through `client` and asserts each matches the recorded
 * plaintext, then checks the account's key material.
 *
 * Items are decrypted one at a time rather than through `decrypt_list`, so a failure names the item
 * that broke instead of failing the whole batch.
 */
export async function validateDecrypted(
  client: PasswordManagerClient,
  vector: UserVector,
): Promise<ValidationSummary> {
  const ciphers = client.vault().ciphers();
  for (const item of vector.vault.ciphers) {
    const decrypted = await ciphers.decrypt(item.encrypted);
    validateAttachmentKeys(decrypted, item);
    expectJsonEqual(decrypted, item.decrypted, `${vector.name}: cipher ${item.id}`);
  }

  const folders = client.vault().folders();
  for (const item of vector.vault.folders) {
    const decrypted = folders.decrypt(item.encrypted);
    expectJsonEqual(decrypted, item.decrypted, `${vector.name}: folder ${item.id}`);
  }

  await validateKeys(client, vector);

  return {
    ciphers: vector.vault.ciphers.length,
    folders: vector.vault.folders.length,
    sendsSkipped: vector.vault.sends.length,
  };
}

/**
 * Asserts the account's key material matches what the vector recorded.
 *
 * For the mid-upgrade account this is the *upgraded* V2 key, not the V1 key the unlock method wrapped —
 * initialization swaps it in using the upgrade token.
 */
export async function validateKeys(
  client: PasswordManagerClient,
  vector: UserVector,
): Promise<void> {
  await validateUserKey(
    client,
    vector.rawCryptographicState.userKey,
    vector.rawCryptographicState.userKeyId,
  );
}

/**
 * Asserts an unlocked client holds `expectedUserKey`, and that the key's id is what its algorithm
 * implies.
 *
 * Split out from {@link validateKeys} so it can be used for accounts that have no committed vector —
 * a freshly registered one, for instance, where the expected key comes from the registration response
 * rather than from a file. Pass `expectedKeyId` when it is known; `undefined` skips the id check and
 * `null` asserts the key carries none, which is the V1 `Aes256CbcHmac` case.
 */
export async function validateUserKey(
  client: PasswordManagerClient,
  expectedUserKey: string,
  expectedKeyId?: string | null,
): Promise<void> {
  const userKey = await client.crypto().get_user_encryption_key();
  expect(userKey.toString()).toBe(expectedUserKey);

  if (expectedKeyId === undefined) {
    return;
  }

  const keyId = CryptoClient.get_key_id_for_symmetric_key(Buffer.from(expectedUserKey, "base64"));
  if (expectedKeyId === null) {
    // A V1 `Aes256CbcHmac` user key carries no key id at all.
    expect(keyId).toBeUndefined();
  } else {
    expect(keyId === undefined ? undefined : Buffer.from(keyId).toString("hex")).toBe(
      expectedKeyId,
    );
  }
}

/**
 * Fields the server owns and stamps on write, so they legitimately differ from what a vector recorded
 * once anything has been written through the SDK.
 */
export const SERVER_OWNED_FIELDS = ["revisionDate"] as const;

/**
 * Like {@link expectJsonEqual}, but ignores fields the server assigns.
 *
 * Use this for anything compared *after* a write. The model server advances `revisionDate` on every
 * write, exactly as the real one does, so a view decrypted afterwards cannot match the vector's
 * recorded plaintext on that field — and asserting it did would mean the fake was lying.
 * {@link expectJsonEqual} stays correct for read-only paths, where nothing has been written.
 */
export function expectPlaintextEqual(
  actual: unknown,
  expected: unknown,
  label: string,
  ignore: readonly string[] = SERVER_OWNED_FIELDS,
): void {
  expectJsonEqual(omitKeys(actual, ignore), omitKeys(expected, ignore), label);
}

function omitKeys(value: unknown, keys: readonly string[]): unknown {
  if (typeof value !== "object" || value === null) {
    return value;
  }
  const rest = { ...(value as Record<string, unknown>) };
  for (const key of keys) {
    delete rest[key];
  }
  return rest;
}

/**
 * Compares two values structurally, treating an absent field, `null` and `undefined` as the same thing.
 *
 * That normalization is required, not a convenience. The vectors are written by `serde_json`, which
 * renders a Rust `None` as `null`; the same value crossing the wasm boundary arrives through
 * `serde_wasm_bindgen`, which renders `None` as `undefined`. So a `CipherView` with no notes reads
 * `"notes": null` in the committed file and `notes: undefined` from the client, for every optional
 * field on every model. Comparing raw JSON would fail on all of them while proving nothing.
 *
 * Everything else is compared exactly, so a genuinely wrong plaintext, date or nested value still fails.
 */
export function expectJsonEqual(actual: unknown, expected: unknown, label: string): void {
  const normalizedActual = normalize(actual);
  const normalizedExpected = normalize(expected);

  if (JSON.stringify(normalizedActual) === JSON.stringify(normalizedExpected)) {
    return;
  }

  try {
    expect(normalizedActual).toEqual(normalizedExpected);
  } catch {
    const differing = differingKeys(normalizedActual, normalizedExpected);
    throw new Error(
      `${label} did not decrypt to the recorded value; differing fields: ${
        differing.length > 0 ? differing.join(", ") : "<whole value>"
      }`,
    );
  }
}

/**
 * `AttachmentView.decryptedKey` is a wasm-only field — it does not exist in the Rust build that writes
 * the vectors, so it can never appear in a recorded value and is dropped before comparison.
 * {@link validateAttachmentKeys} asserts its value separately, which is stricter than skipping it: it
 * checks the attachment key the vector recorded against what the client actually unwrapped.
 *
 * It is a temporary migration field (PM-23005); when it is removed, delete this and the assertion.
 */
const ATTACHMENT_WASM_ONLY_FIELD = "decryptedKey";

/**
 * Asserts the attachment keys the client unwrapped match the ones the vector recorded.
 *
 * Only v2 attachments have a per-attachment key. For v0 and v1 the contents sit under the cipher or user
 * key, so there is nothing to unwrap and `decryptedKey` stays absent.
 */
function validateAttachmentKeys(
  decrypted: { attachments?: unknown },
  item: UserVector["vault"]["ciphers"][number],
): void {
  const attachments = (decrypted.attachments ?? []) as {
    id?: string;
    decryptedKey?: string;
  }[];

  for (const attachment of attachments) {
    const recorded = item.keys.attachments[attachment.id!];
    expect(recorded).toBeDefined();

    if (recorded.version === "V2") {
      expect(attachment.decryptedKey).toBe(recorded.key);
    } else {
      // No per-attachment key exists to unwrap.
      expect(attachment.decryptedKey ?? null).toBeNull();
      expect(recorded.key).toBeNull();
    }
  }

  expect(attachments.length).toBe(Object.keys(item.keys.attachments).length);
}

/**
 * Recursively drops `null`/`undefined` valued keys, and sorts object keys so the comparison and any
 * failure output are stable.
 *
 * `inAttachments` scopes the wasm-only field removal to the elements of an `attachments` array. Dropping
 * every key of that name anywhere would be wrong: `decryptedKey` is also the variant tag of
 * `InitUserCryptoMethod::DecryptedKey`.
 */
function normalize(value: unknown, inAttachments = false): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => normalize(item, inAttachments));
  }
  if (typeof value !== "object" || value === null) {
    return value;
  }
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([key, v]) => {
      if (v === null || v === undefined) {
        return false;
      }
      return !(inAttachments && key === ATTACHMENT_WASM_ONLY_FIELD);
    })
    .map(([k, v]) => [k, normalize(v, k === "attachments")] as const)
    .sort(([a], [b]) => a.localeCompare(b));
  return Object.fromEntries(entries);
}

function differingKeys(actual: unknown, expected: unknown): string[] {
  if (
    typeof actual !== "object" ||
    typeof expected !== "object" ||
    actual === null ||
    expected === null
  ) {
    return [];
  }
  const a = actual as Record<string, unknown>;
  const b = expected as Record<string, unknown>;
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  return [...keys].filter((key) => JSON.stringify(a[key]) !== JSON.stringify(b[key]));
}
