import {
  isDecryptStreamError,
  type BwResult,
  type Cipher,
  type CipherListView,
  type OrganizationId,
} from "@bitwarden/sdk-internal";

import { LoginMethod } from "../../client-emulator/client-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import type { MasterPasswordUserVector } from "../../vectors/load";
import { testVectors } from "../../vectors/test-vectors";

const TIMEOUT = 120_000;

/** Five ciphers, two of them with a cipher key; most cases run against it. */
const VECTOR = testVectors.users.withMasterPassword().get("v1-pbkdf2-password");

/** An organization the account does not belong to, so the store never holds its key. */
const UNKNOWN_ORGANIZATION = "9b1e1d8c-0000-4000-8000-000000000001" as unknown as OrganizationId;

type Item = BwResult<CipherListView, Cipher>;

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

/** A thrown value's error variant, for asserting on SDK errors. */
function variant(error: unknown): string | undefined {
  return isDecryptStreamError(error) ? error.variant : undefined;
}

/** What a promise rejected with, or undefined when it resolved. */
function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    () => undefined,
    (thrown: unknown) => thrown,
  );
}

describe("CiphersClient.list_iterable", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /** Logs `vector` in, syncs and unlocks it; the ciphers come from its client-managed state. */
  async function unlocked(vector: MasterPasswordUserVector) {
    const seeded = harness.server.seedUserTestVector(vector);
    const client = harness.newClientEmulator();
    await client.login(seeded.email, LoginMethod.Password, vector.account.password);
    await client.unlock(vector.account.password);
    const sdk = client.getPasswordManagerClient();
    return { client, sdk, ciphers: sdk.vault().ciphers() };
  }

  testVectors.users.withMasterPassword().each(
    "$name lists the same ciphers as list(), in the same order",
    async (vector) => {
      const { client, ciphers } = await unlocked(vector);
      const stored = await client.local.ciphers.list();

      // 1. List in one call, and through the iterable in chunks smaller than the vault
      const listed = await ciphers.list();
      const items = await collect(ciphers.list_iterable(2));

      // 2. Verify the iterable yields every cipher once, in state order, as list() decrypts it
      expect(items.map(itemId)).toEqual(stored.map((cipher) => String(cipher.id)));
      expect(listed.failures).toEqual([]);
      expect(items.map((item) => (item.ok ? item.value : item.error))).toEqual(listed.successes);
    },
    TIMEOUT,
  );

  it(
    "yields a failure, in its place, for each cipher list() reports as failed",
    async () => {
      const { client, ciphers } = await unlocked(VECTOR);
      // Only a cipher key that cannot be unwrapped fails a whole cipher; moving a cipher with a
      // cipher key into an organization whose key the store lacks does that.
      const stored = await client.local.ciphers.list();
      const failing = stored.find((cipher) => cipher.key != null);
      if (failing === undefined) {
        throw new Error(`${VECTOR.name} has no cipher with a cipher key`);
      }
      await client.local.ciphers.set(String(failing.id), {
        ...failing,
        organizationId: UNKNOWN_ORGANIZATION,
      });

      const listed = await ciphers.list();
      const items = await collect(ciphers.list_iterable(2));

      expect(listed.failures).toHaveLength(1);
      expect(items.map(itemId)).toEqual(stored.map((cipher) => String(cipher.id)));
      expect(items.findIndex((item) => !item.ok)).toBe(stored.indexOf(failing));
      expect(items.filter((item) => !item.ok).map((item) => !item.ok && item.error)).toEqual(
        listed.failures,
      );
      expect(items.filter((item) => item.ok).map((item) => item.ok && item.value)).toEqual(
        listed.successes,
      );
    },
    TIMEOUT,
  );

  it(
    "ends with VaultLocked when the vault is locked between chunks",
    async () => {
      const { client, sdk, ciphers } = await unlocked(VECTOR);
      const stored = await client.local.ciphers.list();
      const iterator = ciphers.list_iterable(2)[Symbol.asyncIterator]();

      // 1. Read the first chunk, then lock in place
      expect((await iterator.next()).done).toBe(false);
      await sdk.unlock().lock();

      // 2. The chunk decrypted before the lock is still handed out
      const buffered = await iterator.next();
      expect(buffered.done ? undefined : itemId(buffered.value)).toBe(String(stored[1].id));

      // 3. The next chunk fails as a whole instead of yielding a failure per cipher
      expect(variant(await rejection(iterator.next()))).toBe("VaultLocked");
      expect(await iterator.next()).toEqual({ value: undefined, done: true });
    },
    TIMEOUT,
  );

  it(
    "ends with a Repository error when the state cannot be read",
    async () => {
      const { client, ciphers } = await unlocked(VECTOR);
      client.local.ciphers.list = async () => {
        throw new Error("storage unavailable");
      };
      const iterator = ciphers.list_iterable()[Symbol.asyncIterator]();

      expect(variant(await rejection(iterator.next()))).toBe("Repository");
      expect(await iterator.next()).toEqual({ value: undefined, done: true });
    },
    TIMEOUT,
  );

  it(
    "keeps working after a for await breaks out early",
    async () => {
      const { client, ciphers } = await unlocked(VECTOR);
      const stored = await client.local.ciphers.list();

      // 1. Break out with a decrypted cipher still waiting in the chunk
      let read = 0;
      for await (const _item of ciphers.list_iterable(2)) {
        read++;
        break;
      }
      expect(read).toBe(1);

      // 2. Verify a second iterable lists the whole vault
      const items = await collect(ciphers.list_iterable(2));
      expect(items.map(itemId)).toEqual(stored.map((cipher) => String(cipher.id)));
    },
    TIMEOUT,
  );

  it(
    "answers overlapping next() calls in call order, across chunks",
    async () => {
      const { client, ciphers } = await unlocked(VECTOR);
      const stored = await client.local.ciphers.list();
      const iterator = ciphers.list_iterable(2)[Symbol.asyncIterator]();

      // 1. Ask for every cipher and two more at once, without awaiting in between
      const results = await Promise.all(
        Array.from({ length: stored.length + 2 }, () => iterator.next()),
      );

      // 2. Verify each cipher came once, in state order, and then the end
      const ids = results.flatMap((result) => (result.done ? [] : [itemId(result.value)]));
      expect(ids).toEqual(stored.map((cipher) => String(cipher.id)));
      expect(results.slice(stored.length).map((result) => result.done)).toEqual([true, true]);
    },
    TIMEOUT,
  );

  it(
    "yields nothing from an empty vault, and reads in one chunk by default",
    async () => {
      const { client, ciphers } = await unlocked(VECTOR);
      const stored = await client.local.ciphers.list();

      expect((await collect(ciphers.list_iterable())).map(itemId)).toEqual(
        stored.map((cipher) => String(cipher.id)),
      );

      await client.local.ciphers.removeAll();
      expect(await collect(ciphers.list_iterable())).toEqual([]);
    },
    TIMEOUT,
  );
});
