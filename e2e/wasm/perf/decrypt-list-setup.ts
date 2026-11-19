// Shared by the decrypt-list harnesses: a V2 account client and a vault encrypted for it.
//
//   generateVault ──► encrypt_list (setupChunk ciphers per call) ──► Cipher[]

import { ok } from "node:assert/strict";

import type { Cipher, CiphersClient } from "@bitwarden/sdk-internal";

import { makeStateBridge, makeV2AccountClient } from "../tests/utils";

import { generateVault } from "./vault-generator";

const CIPHER_KEY_FLAG = "enableCipherKeyEncryption";

/**
 * A client and `size` ciphers, each with a cipher key. Encrypting in calls of `setupChunk` ciphers
 * keeps the growth of WASM memory during setup small.
 */
export async function encryptedVault(
  size: number,
  setupChunk: number,
): Promise<{ ciphers: CiphersClient; vault: Cipher[] }> {
  const client = await makeV2AccountClient(makeStateBridge());
  await client.platform().load_flags(new Map([[CIPHER_KEY_FLAG, true]]));
  const ciphers = client.vault().ciphers();

  const plaintext = generateVault(size);
  const vault: Cipher[] = [];
  for (let i = 0; i < plaintext.length; i += setupChunk) {
    const encrypted = await ciphers.encrypt_list(plaintext.slice(i, i + setupChunk));
    vault.push(...encrypted.map((ctx) => ctx.cipher));
  }
  ok(vault.every((cipher) => cipher.key !== undefined));
  return { ciphers, vault };
}
