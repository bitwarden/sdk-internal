import {
  isDecryptEmergencyAccessAttachmentError,
  type DecryptCipherResult,
  type EmergencyAccessId,
} from "@bitwarden/sdk-internal";

import type { SeedAccount, SeedAttachmentFile } from "../server-emulator/server-emulator";
import { asCipherId } from "../tests/type-assertion-helpers";

import type { ClientEmulator } from "./client-emulator";

export const IGNORED_FIELDS = ["revisionDate", "creationDate"] as const;

/**
 * Decrypts everything an unlocked client's repositories hold, comparing to the plaintext `seed`
 * records. Throws on the first difference.
 *
 * `ignore` names the fields to drop before comparing, and defaults to {@link IGNORED_FIELDS}.
 * A test that has written nothing can pass `[]` to hold the account to every field it started with.
 */
export async function validateVault(
  client: ClientEmulator,
  seed: SeedAccount,
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

  // 3. Download every attachment and compare its decrypted file
  const attachments = sdk.vault().attachments();
  for (const cipher of await client.local.ciphers.list()) {
    const cipherId = String(cipher.id);
    const view = await sdk.vault().ciphers().decrypt(cipher);

    for (const attachment of view.attachments ?? []) {
      const attachmentId = String(attachment.id);
      const label = `attachment ${attachmentId} on cipher ${cipherId}`;
      const recorded = recordedFile(seed, cipherId, attachmentId);

      const url = await attachments.get_attachment_download_url(asCipherId(cipherId), attachmentId);
      const decrypted = attachments.decrypt_buffer(cipher, attachment, await download(url));

      expectFileEqual(decrypted, recorded, label);
    }
  }
}

/**
 * Downloads and decrypts every attachment on the grantor's items an emergency access view
 * returned, comparing to the plaintext `seed` records.
 *
 * Without the grantor's user key, only attachments with a key of their own decrypt. A `V0`
 * attachment has none, so it must be refused as unsupported rather than decrypt to garbage.
 */
export async function validateEmergencyAccessAttachments(
  client: ClientEmulator,
  emergencyAccessId: EmergencyAccessId,
  result: DecryptCipherResult,
  seed: SeedAccount,
): Promise<void> {
  const attachments = client.getPasswordManagerClient().vault().attachments();

  for (const cipher of result.successes) {
    const cipherId = String(cipher.id);

    for (const attachment of cipher.attachments ?? []) {
      const attachmentId = String(attachment.id);
      const label = `attachment ${attachmentId} on cipher ${cipherId}`;
      const recorded = recordedFile(seed, cipherId, attachmentId);

      const url = await attachments.get_attachment_download_url(
        asCipherId(cipherId),
        attachmentId,
        String(emergencyAccessId),
      );
      const encrypted = await download(url);

      if (recorded.version === "V0") {
        expect({
          label,
          error: decryptError(() =>
            attachments.decrypt_emergency_access_buffer(attachment, encrypted),
          ),
        }).toEqual({ label, error: "LegacyAttachmentUnsupported" });
        continue;
      }

      const decrypted = attachments.decrypt_emergency_access_buffer(attachment, encrypted);
      expectFileEqual(decrypted, recorded, label);
    }
  }
}

/** The file `seed` records for an attachment. Throws when it records none. */
function recordedFile(
  seed: SeedAccount,
  cipherId: string,
  attachmentId: string,
): SeedAttachmentFile {
  const cipher = (seed.vault?.ciphers ?? []).find((item) => item.id === cipherId);
  const file = cipher?.attachmentFiles?.[attachmentId];
  if (file === undefined) {
    throw new Error(
      `cipher ${cipherId} holds attachment ${attachmentId}, whose file the vector does not record`,
    );
  }

  return file;
}

/** Fetches an attachment file from the URL the SDK handed back, as a client does. */
async function download(url: string): Promise<Uint8Array> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`downloading ${url} answered ${response.status}`);
  }

  return new Uint8Array(await response.arrayBuffer());
}

/** The variant `decrypt` throws an emergency access attachment error with. Throws otherwise. */
function decryptError(decrypt: () => unknown): string {
  try {
    decrypt();
  } catch (error) {
    if (isDecryptEmergencyAccessAttachmentError(error)) {
      return error.variant;
    }
    throw error;
  }

  throw new Error("expected decryption to be refused, but it succeeded");
}

/** Compares a decrypted file to the plaintext the seed records. */
function expectFileEqual(actual: Uint8Array, recorded: SeedAttachmentFile, label: string): void {
  expect({ label, file: Buffer.from(actual).toString("base64") }).toEqual({
    label,
    file: recorded.decrypted,
  });
}

/**
 * Compares decrypted ciphers to the plaintext `seed` records. Throws on a cipher that failed to
 * decrypt, or one the vector does not record.
 */
export function validateCiphers(
  result: DecryptCipherResult,
  seed: SeedAccount,
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
 * Drops absent fields and `ignore`d keys at every depth.
 *
 * serde_json converts a Rust `None` to `null` while serde_wasm_bindgen converts it to `undefined`,
 * so a raw comparison fails on every optional field while proving nothing.
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
