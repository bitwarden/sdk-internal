// Shared by the iterator harnesses: listing the vault from state in one call or through the
// iterable, against decrypting a vault array the client passes in.
//
//   array                decrypt_list_with_failures(vault)   one call, vault passed in
//   list                 list()                               one call, vault read from state
//   list-iterable        for await over list_iterable()       one result per cipher, from state
//   list-iterable-break  list-iterable, breaking out after BREAK_FRACTION of the vault
//
// The state is a client-managed cipher repository, the JS `TestRepository` the integration tests
// use, registered through `register_client_managed_repositories` as a web client registers its
// own. Its `list()` returns the whole array, which the SDK converts all at once for `list()` and
// a chunk at a time for `list_iterable()`.

import type {
  Cipher,
  CipherListView,
  CiphersClient,
  PasswordManagerClient,
} from "@bitwarden/sdk-internal";

import { TestRepository } from "../client-emulator/local-state";

export type StreamMode = "array" | "list" | "list-iterable" | "list-iterable-break";

export const STREAM_MODES: StreamMode[] = ["array", "list", "list-iterable", "list-iterable-break"];

/** The share of the vault `list-iterable-break` reads before breaking out. */
export const BREAK_FRACTION = 0.1;

/** How many ciphers `decryptVault` reads in `mode` from a vault of `vaultSize`. */
export function expectedReads(mode: StreamMode, vaultSize: number): number {
  return mode === "list-iterable-break" ? Math.ceil(vaultSize * BREAK_FRACTION) : vaultSize;
}

/**
 * Puts `vault` in a client-managed cipher repository and registers it with `client`. A generated
 * cipher has no id, so it is stored under its index.
 */
export async function registerVault(client: PasswordManagerClient, vault: Cipher[]): Promise<void> {
  const ciphers = new TestRepository<Cipher>();
  await ciphers.setBulk(vault.map((cipher, i) => [String(cipher.id ?? i), cipher]));
  client.platform().state().register_client_managed_repositories({
    cipher: ciphers,
    folder: null,
    local_user_data_key_state: null,
    organization_shared_key: null,
    send: null,
    policy: null,
    organization: null,
  });
}

/** What a decrypt produced: the views of the ciphers that decrypted, and how many failed. */
export interface Decrypted {
  views: CipherListView[];
  failures: number;
}

/**
 * Decrypts the vault in `mode`: `vault` for `array`, the registered repository for the others.
 * `chunkSize` applies to the iterable modes.
 */
export async function decryptVault(
  ciphers: CiphersClient,
  vault: Cipher[],
  mode: StreamMode,
  chunkSize: number,
): Promise<Decrypted> {
  switch (mode) {
    case "array": {
      const result = await ciphers.decrypt_list_with_failures(vault);
      return { views: result.successes, failures: result.failures.length };
    }
    case "list": {
      const result = await ciphers.list();
      return { views: result.successes, failures: result.failures.length };
    }
    case "list-iterable":
    case "list-iterable-break": {
      const limit = expectedReads(mode, vault.length);
      const decrypted: Decrypted = { views: [], failures: 0 };
      let reads = 0;
      for await (const item of ciphers.list_iterable(chunkSize)) {
        if (item.ok) {
          decrypted.views.push(item.value);
        } else {
          decrypted.failures++;
        }
        if (++reads === limit) {
          break;
        }
      }
      return decrypted;
    }
  }
}
