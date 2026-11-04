// What a server must refuse, and must say, around a key rotation, so that no client can leave an item
// under a user key the account no longer holds. One test per rule, two backends: the server emulator
// by default, a real server when `BW_LIVE_SERVER_URL` is set. See `live/config.ts` and the Readme.

import type { CipherView } from "@bitwarden/sdk-internal";

import type { ClientEmulator } from "../../client-emulator/client-emulator";
import { TARGET, targetAccount, targetHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import {
  createLogin,
  ensureVaultNotEmpty,
  rotateByPassword,
  session,
  sessions,
} from "./rotate-helpers";

/** The account the emulator is seeded with. A live run uses the configured one instead. */
const V2_VECTOR = testVectors.users.withMasterPassword().get("v2-pbkdf2-blob");

const TIMEOUT = 600_000;

/** Clients creating items while a rotation happens. */
const CREATOR_COUNT = 5;

/** Items every creator lands before the rotation starts, so there is something to carry across. */
const WARMUP_CREATES = 3;

/** Pause between one creator's items. Small, but not zero: a rotation needs a gap to fit in. */
const CREATE_INTERVAL_MS = 25;

/** Upper bound on items per creator, so a server that never refuses fails the test, not hangs it. */
const MAX_CREATES = 200;

/** A rotation that read a vault a create has since grown is refused and has to be retried. */
const MAX_ROTATION_ATTEMPTS = 100;

describe(`rotate user keys, then write with the old key (${TARGET})`, () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = targetHarness();
  });

  afterEach(() => harness.restore());

  /** Every item the account holds, decrypted by a client that just logged in. */
  async function freshVault(client: ClientEmulator): Promise<{
    ids: string[];
    failures: number;
  }> {
    const { successes, failures } = await client
      .getPasswordManagerClient()
      .vault()
      .ciphers()
      .get_all();

    return { ids: successes.map((cipher) => String(cipher.id)), failures: failures.length };
  }

  /**
   * A client that missed a rotation still holds the old user key, and encrypts a new item under it.
   * The server has to refuse it: accepted, the item is one nobody can decrypt any more.
   *
   *   stale ──login───────────────────────────create (old key) ──▶ refused
   *   rotator ──login──rotate ──▶ new key
   */
  it(
    "refuses an item encrypted under the key it held before another client rotated",
    async () => {
      const account = targetAccount(harness, V2_VECTOR);
      const stale = await session(account);
      const rotator = await session(account);
      await ensureVaultNotEmpty(rotator);
      await rotator.sync();

      // 1. One client rotates; the other never hears of it
      await rotateByPassword(
        rotator.getPasswordManagerClient(),
        account.password,
        "CreateIfNeeded",
      );

      // 2. Verify the server refuses what the other one encrypts under the old key
      await expect(
        createLogin(stale, "written with a stale key", "must be refused"),
      ).rejects.toThrow();

      // 3. Verify the account holds nothing a fresh login can't decrypt
      expect((await freshVault(await session(account))).failures).toBe(0);
    },
    TIMEOUT,
  );

  /** What one creator did, as it wrote. */
  interface Creator {
    client: ClientEmulator;
    /** Every item the server acknowledged. The vault has to hold each of them, readable. */
    acked: CipherView[];
    /** Why the first refused item was refused. Absent while items still go through. */
    rejection?: unknown;
  }

  /** Creates items until the server refuses, pausing between them. */
  async function create(creator: Creator): Promise<void> {
    for (let n = 1; n <= MAX_CREATES; n++) {
      try {
        creator.acked.push(await createLogin(creator.client, `created ${n}`, "during a rotation"));
      } catch (error) {
        creator.rejection = error;
        return;
      }

      await new Promise((resolve) => setTimeout(resolve, CREATE_INTERVAL_MS));
    }
  }

  /**
   * A rotation lands in the middle of a stream of new items. Each item the server acknowledged has
   * to end up under the new key: either the rotation read it and re-encrypted it, or it came after
   * the rotation and was refused for its key. Nothing may fall between the two.
   *
   *   creators ──create──create──create──create──✗ refused
   *                            │
   *   rotator ───────────rotate (refused while its vault was short of an item, retried) ──▶ new key
   */
  it(
    "keeps every item created while a rotation lands readable under the new key",
    async () => {
      const account = targetAccount(harness, V2_VECTOR);
      const rotator = await session(account);
      await ensureVaultNotEmpty(rotator);
      const creators: Creator[] = (await sessions(account, CREATOR_COUNT)).map((client) => ({
        client,
        acked: [],
      }));

      // 1. Creators create flat out, while the rotator waits until they have all landed some items
      const creating = Promise.all(creators.map(create));
      while (creators.some((creator) => creator.acked.length < WARMUP_CREATES)) {
        await new Promise((resolve) => setTimeout(resolve, CREATE_INTERVAL_MS));
      }

      // 2. Rotate, retrying while new items keep making what the rotation read incomplete
      let rotated = false;
      for (let attempt = 1; attempt <= MAX_ROTATION_ATTEMPTS && !rotated; attempt++) {
        try {
          await rotator.sync();
          await rotateByPassword(
            rotator.getPasswordManagerClient(),
            account.password,
            "CreateIfNeeded",
          );
          rotated = true;
        } catch {
          // Refused: an item was created after the rotation read the vault. Read it again.
        }
      }
      expect(rotated).toBe(true);

      // 3. Verify new items start being refused, for every creator
      await creating;
      for (const creator of creators) {
        expect(creator.rejection).toBeDefined();
      }

      // 4. Verify a fresh login reads every acknowledged item, and nothing fails to decrypt
      const vault = await freshVault(await session(account));
      expect(vault.failures).toBe(0);
      for (const creator of creators) {
        for (const item of creator.acked) {
          expect(vault.ids).toContain(String(item.id));
        }
      }
    },
    TIMEOUT,
  );

  /**
   * The master-password unlock data in a sync names the user key it holds, so a client can tell
   * stale unlock data from current. After a rotation it has to name the new key, the account's.
   */
  it(
    "names the account's user key in the master-password unlock data it syncs",
    async () => {
      const account = targetAccount(harness, V2_VECTOR);
      const rotator = await session(account);
      await rotateByPassword(
        rotator.getPasswordManagerClient(),
        account.password,
        "CreateIfNeeded",
      );

      // A login syncs, which is what this reads
      const decryption = (await session(account)).lastSync?.userDecryption;

      expect(decryption?.userKeyId).toBeTruthy();
      expect(decryption?.masterPasswordUnlock?.containedKeyId).toBe(decryption?.userKeyId);
    },
    TIMEOUT,
  );
});
