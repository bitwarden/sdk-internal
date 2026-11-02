// Shared by the decrypt-list harnesses: a V2 account client and a vault encrypted for it.
//
//   generateVault ──► encrypt_list (setupChunk ciphers per call) ──► Cipher[]
//
// The modes compare how the list decrypts receive their `Cipher[]`, for `CipherListView` output
// (`decrypt_list_with_failures`) and `CipherView` output (`decrypt_list_full_with_failures`):
//   eager    ..._eager(vault)  input converted in full at the boundary
//   batched  the real method   input converted a batch at a time (250 ciphers in WASM)
//
// The `perf-baselines` methods (`_eager`, `_count`) exist only in the `perf/build.sh`
// build, so they are typed here: `npm test` type-checks this file against the shipped build.

import { ok } from "node:assert/strict";

import type {
  Cipher,
  CiphersClient,
  DecryptCipherListResult,
  DecryptCipherResult,
} from "@bitwarden/sdk-internal";

import { makeStateBridge, makeV2AccountClient } from "../tests/utils";

import { generateVault } from "./vault-generator";

export type DecryptListMode = "eager" | "batched";

export const DECRYPT_LIST_MODES: DecryptListMode[] = ["eager", "batched"];

const CIPHER_KEY_FLAG = "enableCipherKeyEncryption";

/** The `perf-baselines` methods of `CiphersClient`. */
export interface CiphersPerfBaselines {
  decrypt_list_with_failures_eager(ciphers: Cipher[]): Promise<DecryptCipherListResult>;
  decrypt_list_full_with_failures_eager(ciphers: Cipher[]): Promise<DecryptCipherResult>;
  /** Decrypts like `decrypt_list_with_failures` but drops the views; returns the success count. */
  decrypt_list_with_failures_count(ciphers: Cipher[]): Promise<number>;
  /** Decrypts like `decrypt_list_full_with_failures` but drops the views; returns the success count. */
  decrypt_list_full_with_failures_count(ciphers: Cipher[]): Promise<number>;
}

/** `ciphers` with its `perf-baselines` methods, which only the `perf/build.sh` build has. */
export function withPerfBaselines(ciphers: CiphersClient): CiphersClient & CiphersPerfBaselines {
  ok(
    "decrypt_list_with_failures_eager" in ciphers,
    "the SDK lacks the perf-baselines methods; build it with perf/build.sh",
  );
  return ciphers as CiphersClient & CiphersPerfBaselines;
}

/**
 * A client and `size` ciphers, each with a cipher key. Encrypting in calls of `setupChunk` ciphers
 * keeps the growth of WASM memory during setup small.
 */
export async function encryptedVault(
  size: number,
  setupChunk: number,
): Promise<{ ciphers: CiphersClient & CiphersPerfBaselines; vault: Cipher[] }> {
  const client = await makeV2AccountClient(makeStateBridge());
  await client.platform().load_flags(new Map([[CIPHER_KEY_FLAG, true]]));
  const ciphers = withPerfBaselines(client.vault().ciphers());

  const plaintext = generateVault(size);
  const vault: Cipher[] = [];
  for (let i = 0; i < plaintext.length; i += setupChunk) {
    const encrypted = await ciphers.encrypt_list(plaintext.slice(i, i + setupChunk));
    vault.push(...encrypted.map((ctx) => ctx.cipher));
  }
  ok(vault.every((cipher) => cipher.key !== undefined));
  return { ciphers, vault };
}

/** Decrypts `vault` in `mode`. */
export function decryptList(
  ciphers: CiphersClient & CiphersPerfBaselines,
  vault: Cipher[],
  mode: DecryptListMode,
): Promise<DecryptCipherListResult> {
  return mode === "eager"
    ? ciphers.decrypt_list_with_failures_eager(vault)
    : ciphers.decrypt_list_with_failures(vault);
}

/** Decrypts `vault` to full `CipherView`s in `mode`. */
export function decryptFullList(
  ciphers: CiphersClient & CiphersPerfBaselines,
  vault: Cipher[],
  mode: DecryptListMode,
): Promise<DecryptCipherResult> {
  return mode === "eager"
    ? ciphers.decrypt_list_full_with_failures_eager(vault)
    : ciphers.decrypt_list_full_with_failures(vault);
}
