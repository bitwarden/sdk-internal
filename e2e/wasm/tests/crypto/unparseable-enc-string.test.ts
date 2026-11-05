import { validateCiphers } from "../../client-emulator/validate";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import { asEncString } from "../type-assertion-helpers";

const TIMEOUT = 120_000;

/**
 * An `EncString` whose iv decodes to 4 bytes instead of the required 16. It is well-formed base64
 * in the right shape, so it only fails the length check.
 */
const MALFORMED_IV = "2.AAECAw==|Y3Q=|AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

// A malformed `EncString` used to throw while being lifted across the boundary, before the called
// method ran. It now crosses as an unparseable `EncString`, so a single bad item is reported as a
// per-item decryption failure instead of taking down the whole vault.
describe("ciphers with an unparseable EncString", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /** Overwrites the item key of the server's copy of each cipher in `ids` with a malformed one. */
  function corrupt(ids: string[]): void {
    for (const id of ids) {
      const stored = harness.server.db.ciphers.get(id)!;
      harness.server.db.ciphers.update(id, {
        ...stored,
        cipher: { ...stored.cipher, key: asEncString(MALFORMED_IV) },
      });
    }
  }

  testVectors.users.each(
    "$name reports a corrupt cipher from sync as a failure and decrypts the rest",
    async (vector) => {
      // 1. The server holds one cipher whose item key is malformed, and a device syncs it down
      const seeded = harness.server.seedUserTestVector(vector);
      const corruptId = seeded.ciphers()[0].id!;
      corrupt([String(corruptId)]);
      const device = await harness.newUnlockedClient(seeded);

      // 2. Verify the corrupt cipher is reported as a failure, with its raw value intact so the
      //    caller can report or re-send it unchanged
      const result = await device.getPasswordManagerClient().vault().ciphers().get_all();
      expect(result.failures.map((cipher) => [cipher.id, cipher.key])).toEqual([
        [corruptId, MALFORMED_IV],
      ]);

      // 3. Verify every other cipher still decrypts
      validateCiphers({ ...result, failures: [] }, seeded.seed, []);
    },
    TIMEOUT,
  );

  it(
    "reports every cipher as a failure when they are all corrupt",
    async () => {
      // 1. The server holds only corrupt ciphers, and a device syncs them down
      const seeded = harness.server.seedUserTestVector(testVectors.users.get("v2-pbkdf2-blob"));
      const ids = seeded.ciphers().map((cipher) => String(cipher.id));
      corrupt(ids);
      const device = await harness.newUnlockedClient(seeded);

      // 2. Verify every cipher is reported as a failure
      const result = await device.getPasswordManagerClient().vault().ciphers().get_all();
      expect(result.successes).toEqual([]);
      expect(result.failures.map((cipher) => String(cipher.id)).sort()).toEqual(ids.sort());
    },
    TIMEOUT,
  );
});
