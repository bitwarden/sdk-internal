// Shared by the iterator harnesses: decrypting a vault in one call, through the iterable, or
// through the explicit stream handles that serve as baselines.
//
//   array                   decrypt_list_with_failures(vault)                 one call
//   item                    stream.next_item()         until undefined        one call per cipher
//   chunk                   stream.next_chunk()        until []               one call per chunk
//   async-source-item       await stream.next_item_async()                    one Promise per cipher
//   async-source-chunk      await stream.next_chunk_async()                   one Promise per chunk
//   iterable-results        for await over decrypt_list_iterable              one result per cipher
//   iterable-results-break  iterable-results, breaking out after BREAK_FRACTION of the vault
//
// The streams pull encrypted ciphers from a JS source over the vault array, so WASM memory holds
// only the chunk being decrypted. `item` and `chunk` use a sync `CipherSource`; the others use an
// `AsyncCipherSource`, whose `nextChunk` resolves in a microtask, the shape of an async repository
// such as IndexedDB. The cost of IndexedDB itself is not modelled.

import type {
  AsyncCipherSource,
  Cipher,
  CipherListView,
  CipherSource,
  CiphersClient,
  OrganizationId,
} from "@bitwarden/sdk-internal";

export type StreamMode =
  | "array"
  | "item"
  | "chunk"
  | "async-source-item"
  | "async-source-chunk"
  | "iterable-results"
  | "iterable-results-break";

export const STREAM_MODES: StreamMode[] = [
  "array",
  "item",
  "chunk",
  "async-source-item",
  "async-source-chunk",
  "iterable-results",
  "iterable-results-break",
];

/** The share of the vault `iterable-results-break` reads before breaking out. */
export const BREAK_FRACTION = 0.1;

/** An organization no test account belongs to, so the store never holds its key. */
const UNKNOWN_ORGANIZATION = "9b1e1d8c-0000-4000-8000-000000000001" as unknown as OrganizationId;

/** Whether `mode` pulls one cipher per call from the source. */
export function isItemMode(mode: StreamMode): boolean {
  return mode === "item" || mode === "async-source-item";
}

/** How many ciphers `decryptVault` reads in `mode` from a vault of `vaultSize`. */
export function expectedReads(mode: StreamMode, vaultSize: number): number {
  return mode === "iterable-results-break" ? Math.ceil(vaultSize * BREAK_FRACTION) : vaultSize;
}

/**
 * Makes every `1 / fraction`-th cipher of `vault` fail to decrypt, by moving it into an
 * organization whose key the store does not hold. Every cipher of a generated vault has a cipher
 * key, which then cannot be unwrapped. Returns the vault and the number of failing ciphers.
 */
export function corruptVault(vault: Cipher[], fraction: number): [Cipher[], number] {
  if (fraction <= 0) {
    return [vault, 0];
  }
  const every = Math.round(1 / fraction);
  const corrupted = vault.map((cipher, i) =>
    i % every === every - 1 ? { ...cipher, organizationId: UNKNOWN_ORGANIZATION } : cipher,
  );
  return [corrupted, Math.floor(vault.length / every)];
}

/** A source handing out `vault` in order, at most `max` ciphers per call. */
export function cipherSource(vault: Cipher[]): CipherSource {
  let next = 0;
  return {
    nextChunk(max: number): Cipher[] | undefined {
      if (next >= vault.length) {
        return undefined;
      }
      const chunk = vault.slice(next, next + max);
      next += chunk.length;
      return chunk;
    },
  };
}

/** {@link cipherSource}, resolving each chunk in a microtask. */
export function asyncCipherSource(vault: Cipher[]): AsyncCipherSource {
  const source = cipherSource(vault);
  return {
    async nextChunk(max: number): Promise<Cipher[] | undefined> {
      return source.nextChunk(max);
    },
  };
}

/** What a decrypt produced: the views of the ciphers that decrypted, and how many failed. */
export interface Decrypted {
  views: CipherListView[];
  failures: number;
}

/**
 * Decrypts `vault` in `mode`. `chunkSize` applies to the chunk modes and the iterable.
 *
 * The baselines count failures only; the iterable and the array call also hand the failed ciphers
 * back, which this drops after counting.
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
    case "iterable-results":
    case "iterable-results-break": {
      const limit = expectedReads(mode, vault.length);
      const decrypted: Decrypted = { views: [], failures: 0 };
      let reads = 0;
      for await (const item of ciphers.decrypt_list_iterable(asyncCipherSource(vault), chunkSize)) {
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
    case "async-source-item":
    case "async-source-chunk": {
      const stream = await ciphers.decrypt_list_async_stream(asyncCipherSource(vault), chunkSize);
      const views: CipherListView[] = [];
      try {
        if (mode === "async-source-item") {
          for (
            let view = await stream.next_item_async();
            view !== undefined;
            view = await stream.next_item_async()
          ) {
            views.push(view);
          }
        } else {
          for (
            let chunk = await stream.next_chunk_async();
            chunk.length > 0;
            chunk = await stream.next_chunk_async()
          ) {
            views.push(...chunk);
          }
        }
        return { views, failures: stream.failure_count() };
      } finally {
        // A WASM-owned handle keeps its memory until `free()` or garbage collection.
        stream.free();
      }
    }
    case "item":
    case "chunk": {
      const stream = await ciphers.decrypt_list_stream(cipherSource(vault), chunkSize);
      const views: CipherListView[] = [];
      try {
        if (mode === "item") {
          for (let view = stream.next_item(); view !== undefined; view = stream.next_item()) {
            views.push(view);
          }
        } else {
          for (let chunk = stream.next_chunk(); chunk.length > 0; chunk = stream.next_chunk()) {
            views.push(...chunk);
          }
        }
        return { views, failures: stream.failure_count() };
      } finally {
        stream.free();
      }
    }
  }
}
