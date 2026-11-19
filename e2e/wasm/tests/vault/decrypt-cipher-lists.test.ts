import {
  isDecryptError,
  isDecryptListError,
  type Cipher,
  type CiphersClient,
  type OrganizationId,
} from "@bitwarden/sdk-internal";

import { LoginMethod } from "../../client-emulator/client-emulator";
import { generateVault } from "../../perf/vault-generator";
import { testHarness, type TestHarness } from "../../test-harness";
import type { MasterPasswordUserVector } from "../../vectors/load";
import { testVectors } from "../../vectors/test-vectors";
import { makeStateBridge, makeV2AccountClient } from "../utils";

const TIMEOUT = 120_000;

/** Five ciphers, two of them with a cipher key. */
const VECTOR = testVectors.users.withMasterPassword().get("v1-pbkdf2-password");

/** An organization the account does not belong to, so the store never holds its key. */
const UNKNOWN_ORGANIZATION = "9b1e1d8c-0000-4000-8000-000000000001" as unknown as OrganizationId;

/**
 * How many ciphers the SDK converts and decrypts at a time: the batch size of
 * `KeyStore::decrypt_iter` in `bitwarden-crypto`, which is 250 in single-threaded WASM.
 */
const BATCH_SIZE = 250;

/** The feature flag that has the SDK decrypt ciphers with `StrictDecrypt`. */
const STRICT_CIPHER_DECRYPTION = "pm-34500-strict-cipher-decryption";

/** A thrown value's error variant, for asserting on SDK errors. */
function variant(error: unknown): string | undefined {
  return isDecryptListError(error) || isDecryptError(error) ? error.variant : undefined;
}

/**
 * `value` without its `null` and `undefined` properties. A cipher the SDK returns leaves out the
 * empty fields a stored cipher has as `null`.
 */
function withoutEmptyFields(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(withoutEmptyFields);
  }
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([, field]) => field != null)
        .map(([key, field]) => [key, withoutEmptyFields(field)]),
    );
  }
  return value;
}

/** What a promise rejects with, or `undefined` if it resolves. */
function rejection(call: Promise<unknown>): Promise<unknown> {
  return call.then(
    () => undefined,
    (thrown: unknown) => thrown,
  );
}

/**
 * A cipher whose cipher key cannot be unwrapped fails as a whole; moving one with a cipher key into
 * an organization whose key the store lacks does that.
 */
function failing(cipher: Cipher): Cipher {
  return { ...cipher, organizationId: UNKNOWN_ORGANIZATION };
}

/**
 * A cipher with a field that does not decrypt: `name`, taken from `other`, which is encrypted under
 * another cipher key. Strict decryption fails such a cipher; lenient decryption does not.
 */
function withForeignName(cipher: Cipher, other: Cipher): Cipher {
  return { ...cipher, name: other.name };
}

/**
 * Verifies the list decrypts against decrypting each cipher on its own: `decrypt` for full views,
 * and a one-cipher `decrypt_list` for list views, which never spans a batch.
 */
async function expectPerCipherResults(
  ciphers: CiphersClient,
  input: Cipher[],
  failingIndexes: number[],
) {
  const decryptable = input.filter((_, i) => !failingIndexes.includes(i));
  const failures = failingIndexes.map((i) => input[i]);

  // 1. Decrypt each decryptable cipher on its own, as the reference
  const listViews = [];
  const views = [];
  for (const cipher of decryptable) {
    listViews.push(...(await ciphers.decrypt_list([cipher])));
    views.push(await ciphers.decrypt(cipher));
  }

  // 2. Verify the list decrypts agree exactly, in order, and return the failing ciphers as given
  const list = await ciphers.decrypt_list_with_failures(input);
  expect(list.successes).toEqual(listViews);
  expect(withoutEmptyFields(list.failures)).toEqual(withoutEmptyFields(failures));
  const full = await ciphers.decrypt_list_full_with_failures(input);
  expect(full.successes).toEqual(views);
  expect(withoutEmptyFields(full.failures)).toEqual(withoutEmptyFields(failures));
  if (failures.length === 0) {
    expect(await ciphers.decrypt_list(input)).toEqual(listViews);
  } else {
    expect(variant(await rejection(ciphers.decrypt_list(input)))).toBe("Crypto");
  }
}

// `decrypt_list`, `decrypt_list_with_failures` and `decrypt_list_full_with_failures` convert their
// `Cipher[]` a batch at a time inside the SDK.
describe("CiphersClient list decrypts", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  async function unlocked(vector: MasterPasswordUserVector, flags?: Map<string, boolean>) {
    const seeded = harness.server.seedUserTestVector(vector);
    const client = harness.newClientEmulator();
    await client.login(seeded.email, LoginMethod.Password, vector.account.password);
    await client.unlock(vector.account.password);
    const pm = client.getPasswordManagerClient();
    if (flags) {
      await pm.platform().load_flags(flags);
    }
    return {
      platform: pm.platform(),
      ciphers: pm.vault().ciphers(),
      encrypted: await client.local.ciphers.list(),
    };
  }

  testVectors.users.withMasterPassword().each(
    "$name decrypts as each cipher on its own does, failures included",
    async (vector) => {
      const { ciphers, encrypted } = await unlocked(vector);
      const failingIndex = encrypted.findIndex((cipher) => cipher.key != null);
      const input = encrypted.map((cipher, i) => (i === failingIndex ? failing(cipher) : cipher));

      await expectPerCipherResults(ciphers, input, failingIndex === -1 ? [] : [failingIndex]);
    },
    TIMEOUT,
  );

  it(
    "decrypts a list longer than two batches, with failures on both sides of a batch boundary",
    async () => {
      // 1. Encrypt a vault where every cipher has a cipher key
      const client = await makeV2AccountClient(makeStateBridge());
      await client.platform().load_flags(new Map([["enableCipherKeyEncryption", true]]));
      const ciphers = client.vault().ciphers();
      const encrypted = (await ciphers.encrypt_list(generateVault(BATCH_SIZE * 2 + 100))).map(
        (ctx) => ctx.cipher,
      );
      expect(encrypted.every((cipher) => cipher.key != null)).toBe(true);

      // 2. Make the last cipher of the first batch and the first of the second fail
      const failingIndexes = [BATCH_SIZE - 1, BATCH_SIZE];
      const input = encrypted.map((cipher, i) =>
        failingIndexes.includes(i) ? failing(cipher) : cipher,
      );

      // 3. Verify against decrypting each cipher on its own
      await expectPerCipherResults(ciphers, input, failingIndexes);
      await expectPerCipherResults(ciphers, encrypted, []);
    },
    TIMEOUT,
  );

  describe("with strict cipher decryption", () => {
    const strict = new Map([[STRICT_CIPHER_DECRYPTION, true]]);

    testVectors.users.withMasterPassword().each(
      "$name decrypts as each cipher on its own does, failures included",
      async (vector) => {
        const { ciphers, encrypted } = await unlocked(vector, strict);
        const failingIndex = encrypted.findIndex((cipher) => cipher.key != null);
        const input = encrypted.map((cipher, i) => (i === failingIndex ? failing(cipher) : cipher));

        await expectPerCipherResults(ciphers, input, failingIndex === -1 ? [] : [failingIndex]);
        await expectPerCipherResults(ciphers, encrypted, []);
      },
      TIMEOUT,
    );

    it(
      "decrypts a list longer than two batches, with failures on both sides of a batch boundary",
      async () => {
        // 1. Repeat the vector's ciphers past two batches. They are in the field-level format,
        // whose fields strict decryption fails on one by one.
        const { platform, ciphers, encrypted } = await unlocked(VECTOR);
        const withKey = encrypted.filter((cipher) => cipher.key != null);
        expect(withKey.length).toBeGreaterThanOrEqual(2);
        const repeated = Array.from(
          { length: BATCH_SIZE * 2 + 100 },
          (_, i) => encrypted[i % encrypted.length],
        );
        const input = [...repeated];

        // 2. Make the last cipher of the first batch fail as a whole, and the first of the second
        // fail only on a field
        input[BATCH_SIZE - 1] = failing(withKey[0]);
        input[BATCH_SIZE] = withForeignName(withKey[0], withKey[1]);

        // 3. Verify the field failure decrypts leniently, so only strict decryption fails it
        await ciphers.decrypt(input[BATCH_SIZE]);

        // 4. Turn on strict decryption and verify against decrypting each cipher on its own
        await platform.load_flags(strict);
        expect(variant(await rejection(ciphers.decrypt(input[BATCH_SIZE])))).toBe("Crypto");
        await expectPerCipherResults(ciphers, input, [BATCH_SIZE - 1, BATCH_SIZE]);
        await expectPerCipherResults(ciphers, repeated, []);
      },
      TIMEOUT,
    );
  });

  describe.each([
    { name: "decrypt_list", decrypt: "list" as const },
    { name: "decrypt_list_with_failures", decrypt: "listWithFailures" as const },
    { name: "decrypt_list_full_with_failures", decrypt: "fullWithFailures" as const },
  ])("$name", ({ decrypt }) => {
    function call(ciphers: CiphersClient, input: Cipher[]): Promise<unknown> {
      switch (decrypt) {
        case "list":
          return ciphers.decrypt_list(input);
        case "listWithFailures":
          return ciphers.decrypt_list_with_failures(input);
        case "fullWithFailures":
          return ciphers.decrypt_list_full_with_failures(input);
      }
    }

    it(
      "rejects with InvalidInput when an entry is not a cipher",
      async () => {
        const { ciphers, encrypted } = await unlocked(VECTOR);
        const input = [encrypted[0], { not: "a cipher" }, encrypted[1]] as unknown as Cipher[];

        const error = await rejection(call(ciphers, input));

        expect(variant(error)).toBe("InvalidInput");
        expect((error as Error).message).toContain("Item 1 of the list is invalid");
      },
      TIMEOUT,
    );

    it(
      "names the entry's index in the whole list when it is past the first batch",
      async () => {
        const { ciphers, encrypted } = await unlocked(VECTOR);
        const input = Array.from({ length: BATCH_SIZE + 2 }, () => encrypted[0]);
        input[BATCH_SIZE + 1] = { not: "a cipher" } as unknown as Cipher;

        const error = await rejection(call(ciphers, input));

        expect(variant(error)).toBe("InvalidInput");
        expect((error as Error).message).toContain(`Item ${BATCH_SIZE + 1} of the list is invalid`);
      },
      TIMEOUT,
    );

    it(
      "throws when called, as a whole-array conversion does, for a value that is not a list",
      async () => {
        const { ciphers } = await unlocked(VECTOR);
        const input = null as unknown as Cipher[];

        // The generated JavaScript copies the array when the call is made, so it throws there, as
        // for a `Vec` parameter such as `encrypt_list`'s.
        expect(() => ciphers.encrypt_list(input as never)).toThrow(TypeError);
        expect(() => call(ciphers, input)).toThrow(TypeError);
      },
      TIMEOUT,
    );

    it(
      "decrypts the array as it was when called, not as changed afterwards",
      async () => {
        const { ciphers, encrypted } = await unlocked(VECTOR);
        const input = [...encrypted];

        // 1. Start the call, then empty the array before the SDK reads it
        const pending = call(ciphers, input);
        input.length = 0;

        // 2. Verify every cipher that was in the array was decrypted
        const result = (await pending) as unknown[] | { successes: unknown[] };
        const decrypted = Array.isArray(result) ? result : result.successes;
        expect(decrypted).toHaveLength(encrypted.length);
      },
      TIMEOUT,
    );
  });
});
