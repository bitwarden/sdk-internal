import {
  isDecryptStreamError,
  type AsyncCipherSource,
  type BwResult,
  type Cipher,
  type CipherListView,
  type OrganizationId,
  type PasswordManagerClient,
} from "@bitwarden/sdk-internal";

import { LoginMethod } from "../../client-emulator/client-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import type { MasterPasswordUserVector } from "../../vectors/load";

const TIMEOUT = 120_000;

/** Five ciphers, two of them with a cipher key; most cases run against it. */
const VECTOR = testVectors.users.withMasterPassword().get("v1-pbkdf2-password");

/** An organization the account does not belong to, so the store never holds its key. */
const UNKNOWN_ORGANIZATION = "9b1e1d8c-0000-4000-8000-000000000001" as unknown as OrganizationId;

type Item = BwResult<CipherListView, Cipher>;

/** One `nextChunk` result: ciphers, the end of the source, or a failure. */
type Step = Cipher[] | "end" | { throws: unknown } | { rejects: unknown };

/** A source playing back `steps`, then ending. Records the `max` of every call. */
function scriptedSource(steps: Step[]): AsyncCipherSource & { pulls: number[] } {
  const pending = [...steps];
  const pulls: number[] = [];
  return {
    pulls,
    nextChunk(max: number): Promise<Cipher[] | undefined> {
      pulls.push(max);
      const step = pending.shift() ?? "end";
      if (step === "end") {
        return Promise.resolve(undefined);
      }
      if (Array.isArray(step)) {
        return Promise.resolve(step);
      }
      if ("throws" in step) {
        throw step.throws;
      }
      return Promise.reject(step.rejects);
    },
  };
}

/** A source over `ciphers`, as an async repository would supply them. Records every `max`. */
function vaultSource(ciphers: Cipher[]): AsyncCipherSource & { pulls: number[] } {
  let next = 0;
  const pulls: number[] = [];
  return {
    pulls,
    async nextChunk(max: number): Promise<Cipher[] | undefined> {
      pulls.push(max);
      if (next >= ciphers.length) {
        return undefined;
      }
      const chunk = ciphers.slice(next, next + max);
      next += chunk.length;
      return chunk;
    },
  };
}

async function collect(items: AsyncIterable<Item>): Promise<Item[]> {
  const collected: Item[] = [];
  for await (const item of items) {
    collected.push(item);
  }
  return collected;
}

/** The id of the cipher behind an item, decrypted or not. */
function itemId(item: Item): string {
  return String(item.ok ? item.value.id : item.error.id);
}

/** The login username of a list view, if it is a login. */
function username(view: CipherListView): string | undefined {
  return typeof view.type === "object" && "login" in view.type
    ? view.type.login.username
    : undefined;
}

/** A thrown value's error variant, for asserting on SDK errors. */
function variant(error: unknown): string | undefined {
  return isDecryptStreamError(error) ? error.variant : undefined;
}

describe("decrypt_list_iterable", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /** Logs `vector` in and unlocks it; returns its client and its encrypted ciphers in state. */
  async function unlocked(vector: MasterPasswordUserVector) {
    const seeded = harness.server.seedUserTestVector(vector);
    const client = harness.newClientEmulator();
    await client.login(seeded.email, LoginMethod.Password, vector.account.password);
    await client.unlock(vector.account.password);
    const sdk: PasswordManagerClient = client.getPasswordManagerClient();
    return {
      seeded,
      sdk,
      ciphers: sdk.vault().ciphers(),
      encrypted: await client.local.ciphers.list(),
    };
  }

  testVectors.users.withMasterPassword().each(
    "$name lists its whole vault with for await",
    async (vector) => {
      const { seeded, ciphers, encrypted } = await unlocked(vector);

      // 1. Iterate in chunks smaller than the vault, so more than one chunk is pulled
      const items = await collect(ciphers.decrypt_list_iterable(vaultSource(encrypted), 2));

      // 2. Verify every cipher arrived once, decrypted, with its plaintext
      const recorded = seeded.seed.vault?.ciphers ?? [];
      expect(items.map(itemId)).toEqual(encrypted.map((cipher) => String(cipher.id)));
      expect(items.map(itemId).sort()).toEqual(recorded.map((cipher) => cipher.id).sort());
      for (const item of items) {
        if (!item.ok) {
          throw new Error(`cipher ${itemId(item)} failed to decrypt`);
        }
        const decrypted = recorded.find((cipher) => cipher.id === String(item.value.id))?.decrypted;
        expect({ name: item.value.name, username: username(item.value) }).toEqual({
          name: decrypted?.name,
          username: decrypted?.login?.username ?? undefined,
        });
      }
    },
    TIMEOUT,
  );

  describe.each([
    { name: VECTOR.name, vector: VECTOR },
    {
      name: "v2-pbkdf2-blob",
      vector: testVectors.users.withMasterPassword().get("v2-pbkdf2-blob"),
    },
  ])("$name", ({ vector }) => {
    it(
      "yields a cipher that fails to decrypt as a failure in its place",
      async () => {
        const { ciphers, encrypted } = await unlocked(vector);
        // Only a cipher key that cannot be unwrapped fails a whole cipher; a key missing for a
        // single field blanks that field. Moving a cipher with a cipher key into an organization
        // whose key the store lacks does that.
        const failing = encrypted.flatMap((cipher, i) => (cipher.key == null ? [] : [i]));
        const source = encrypted.map((cipher, i) =>
          i === failing[0] ? { ...cipher, organizationId: UNKNOWN_ORGANIZATION } : cipher,
        );

        const items = await collect(ciphers.decrypt_list_iterable(vaultSource(source), 2));

        expect(items.map(itemId)).toEqual(encrypted.map((cipher) => String(cipher.id)));
        expect(items.map((item) => item.ok)).toEqual(encrypted.map((_, i) => i !== failing[0]));
        // The failure carries the same encrypted cipher decrypt_list_with_failures reports.
        const failure = items[failing[0]];
        const reference = await ciphers.decrypt_list_with_failures(source);
        expect(reference.failures).toHaveLength(1);
        expect(failure.ok ? undefined : failure.error).toEqual(reference.failures[0]);
      },
      TIMEOUT,
    );
  });

  it(
    "yields every failing cipher of a chunk and goes on with the next chunk",
    async () => {
      const { ciphers, encrypted } = await unlocked(VECTOR);
      const failing = encrypted.flatMap((cipher, i) => (cipher.key == null ? [] : [i]));
      expect(failing.length).toBeGreaterThan(1);
      const source = encrypted.map((cipher, i) =>
        failing.includes(i) ? { ...cipher, organizationId: UNKNOWN_ORGANIZATION } : cipher,
      );

      const items = await collect(ciphers.decrypt_list_iterable(vaultSource(source), 2));

      expect(items.map(itemId)).toEqual(encrypted.map((cipher) => String(cipher.id)));
      expect(items.map((item) => item.ok)).toEqual(encrypted.map((_, i) => !failing.includes(i)));
    },
    TIMEOUT,
  );

  describe.each([
    { how: "throws", step: (error: Error): Step => ({ throws: error }) },
    { how: "rejects", step: (error: Error): Step => ({ rejects: error }) },
  ])("a source that $how partway", ({ step }) => {
    it(
      "rejects next() once with its error, then is done and pulls nothing more",
      async () => {
        const { ciphers, encrypted } = await unlocked(VECTOR);
        const error = new Error("repository unavailable");
        const source = scriptedSource([encrypted.slice(0, 2), step(error), encrypted.slice(2)]);
        const iterator = ciphers.decrypt_list_iterable(source, 2)[Symbol.asyncIterator]();

        // 1. The first chunk arrives
        expect((await iterator.next()).done).toBe(false);
        expect((await iterator.next()).done).toBe(false);

        // 2. The failing pull rejects with the source's own error
        await expect(iterator.next()).rejects.toBe(error);

        // 3. Verify the iteration is over and the source is not pulled again
        expect(await iterator.next()).toEqual({ value: undefined, done: true });
        expect(await iterator.next()).toEqual({ value: undefined, done: true });
        expect(source.pulls).toHaveLength(2);
      },
      TIMEOUT,
    );
  });

  it(
    "ends with VaultLocked when the vault is locked between pulls",
    async () => {
      const { sdk, ciphers, encrypted } = await unlocked(VECTOR);
      const source = vaultSource(encrypted);
      const iterator = ciphers.decrypt_list_iterable(source, 2)[Symbol.asyncIterator]();

      // 1. Read the first chunk, then lock in place
      expect((await iterator.next()).done).toBe(false);
      await sdk.unlock().lock();

      // 2. The chunk decrypted before the lock is still handed out
      const buffered = await iterator.next();
      expect(buffered.done ? undefined : itemId(buffered.value)).toBe(String(encrypted[1].id));

      // 3. The next pull fails as a whole instead of yielding a failure per cipher
      const error = await iterator.next().then(
        () => undefined,
        (thrown: unknown) => thrown,
      );
      expect(variant(error)).toBe("VaultLocked");
      expect(await iterator.next()).toEqual({ value: undefined, done: true });
      expect(source.pulls).toHaveLength(2);
    },
    TIMEOUT,
  );

  it(
    "keeps working after a for await breaks out early",
    async () => {
      const { ciphers, encrypted } = await unlocked(VECTOR);
      expect(encrypted.length).toBeGreaterThan(2);

      // 1. Break out with a decrypted cipher still waiting in the chunk
      const broken = vaultSource(encrypted);
      let read = 0;
      for await (const _item of ciphers.decrypt_list_iterable(broken, 2)) {
        read++;
        break;
      }
      expect({ read, pulls: broken.pulls.length }).toEqual({ read: 1, pulls: 1 });

      // 2. Verify a second iterable lists the whole vault
      const items = await collect(ciphers.decrypt_list_iterable(vaultSource(encrypted), 2));
      expect(items.map(itemId)).toEqual(encrypted.map((cipher) => String(cipher.id)));
    },
    TIMEOUT,
  );

  it(
    "answers overlapping next() calls in call order, across chunks",
    async () => {
      const { ciphers, encrypted } = await unlocked(VECTOR);
      const iterator = ciphers
        .decrypt_list_iterable(vaultSource(encrypted), 2)
        [Symbol.asyncIterator]();

      // 1. Ask for every cipher and two more at once, without awaiting in between
      const results = await Promise.all(
        Array.from({ length: encrypted.length + 2 }, () => iterator.next()),
      );

      // 2. Verify each cipher came once, in source order, and then the end
      const ids = results.flatMap((result) => (result.done ? [] : [itemId(result.value)]));
      expect(ids).toEqual(encrypted.map((cipher) => String(cipher.id)));
      expect(results.slice(encrypted.length).map((result) => result.done)).toEqual([true, true]);
    },
    TIMEOUT,
  );

  describe("edge cases", () => {
    it(
      "yields nothing from an empty source",
      async () => {
        const { ciphers } = await unlocked(VECTOR);
        const source = scriptedSource([]);

        expect(await collect(ciphers.decrypt_list_iterable(source, 10))).toEqual([]);
        expect(source.pulls).toEqual([10]);
      },
      TIMEOUT,
    );

    it(
      "pulls one cipher at a time for a chunk size of 0",
      async () => {
        const { ciphers, encrypted } = await unlocked(VECTOR);
        const source = vaultSource(encrypted);

        const items = await collect(ciphers.decrypt_list_iterable(source, 0));

        expect(items).toHaveLength(encrypted.length);
        expect(new Set(source.pulls)).toEqual(new Set([1]));
      },
      TIMEOUT,
    );

    it(
      "takes the whole vault in one pull when the chunk size exceeds it",
      async () => {
        const { ciphers, encrypted } = await unlocked(VECTOR);
        const source = vaultSource(encrypted);

        const items = await collect(ciphers.decrypt_list_iterable(source, 1000));

        expect(items.map(itemId)).toEqual(encrypted.map((cipher) => String(cipher.id)));
        // One pull for the vault, one that finds the end.
        expect(source.pulls).toEqual([1000, 1000]);
      },
      TIMEOUT,
    );

    it(
      "skips empty chunks from the source",
      async () => {
        const { ciphers, encrypted } = await unlocked(VECTOR);
        const source = scriptedSource([
          [],
          encrypted.slice(0, 2),
          [],
          [],
          encrypted.slice(2),
          [],
          "end",
        ]);

        const items = await collect(ciphers.decrypt_list_iterable(source, 2));

        expect(items.map(itemId)).toEqual(encrypted.map((cipher) => String(cipher.id)));
      },
      TIMEOUT,
    );
  });
});

// Type-level check, compiled by `npm run typecheck`: an item has its `value` only once `ok` is
// known to be true, and its `error` only once it is known to be false.
export function describeItem(item: BwResult<CipherListView, Cipher>): string {
  // @ts-expect-error `value` is not known to exist before narrowing on `ok`.
  void item.value;
  return item.ok ? item.value.name : `failed: ${String(item.error.id)}`;
}
