// Nothing may end up under a user key the account no longer holds. Runs on the emulator, or on a
// real server when `BW_LIVE_SERVER_URL` is set; see `live/config.ts` and the Readme.

import type { CipherView } from "@bitwarden/sdk-internal";

import type { ClientEmulator } from "../../client-emulator/client-emulator";
import {
  TARGET,
  targetAccount,
  targetHarness,
  type TargetAccount,
  type TestHarness,
} from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import {
  createLogin,
  ensureVaultNotEmpty,
  rotateByPassword as rotate,
  session,
  sessions,
} from "./rotate-helpers";

const TIMEOUT = 600_000;

const V2_VECTOR = testVectors.users.withMasterPassword().get("v2-pbkdf2-blob");

/** Clients creating items while a rotation lands. */
const CREATOR_COUNT = 5;

/** Pause between one creator's items. Small, but not zero: a rotation needs a gap to fit in. */
const CREATE_INTERVAL_MS = 25;

/** Upper bound on items per creator, so a server that never refuses fails the test, not hangs it. */
const MAX_CREATES = 200;

/** A rotation that read a vault a new item has since grown is refused, and is retried. */
const MAX_ROTATION_ATTEMPTS = 100;

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

describe(`rotate user keys, then write with the old key (${TARGET})`, () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = targetHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /** Asserts a client that logs in fresh decrypts every item the account holds. */
  async function assertNothingUndecryptable(account: TargetAccount): Promise<void> {
    const client = await session(account);
    const { failures } = await client.getPasswordManagerClient().vault().ciphers().get_all();
    expect(failures).toHaveLength(0);
  }

  /**
   * A client that missed a rotation still holds the old user key. The server refuses an item it
   * encrypts under that key; accepted, nobody could decrypt the item any more.
   *
   *   rotator ──login──▶ rotate ──▶ K2
   *                         │
   *   stale   ──login(K1)───┴──────▶ create(K1) ──▶ refused
   */
  it(
    "refuses an item encrypted under the key from before another client rotated",
    async () => {
      const account = targetAccount(harness, V2_VECTOR);
      const stale = await session(account);
      const rotator = await session(account);
      await ensureVaultNotEmpty(rotator);

      // 1. One client rotates; the other never hears of it
      await rotate(rotator.getPasswordManagerClient(), account.password, "CreateIfNeeded");

      // 2. Verify the server refuses the item the other one encrypts under the old key
      await expect(createLogin(stale, "stale", "under the old key")).rejects.toThrow();

      // 3. Verify a client that logs in fresh decrypts everything the account holds
      await assertNothingUndecryptable(account);
    },
    TIMEOUT,
  );

  /** Creates items one after another until the server refuses one. Whether it was refused. */
  async function createUntilRefused(
    client: ClientEmulator,
    created: CipherView[],
  ): Promise<boolean> {
    for (let n = 1; n <= MAX_CREATES; n++) {
      try {
        created.push(await createLogin(client, `created ${n}`, "during a rotation"));
      } catch {
        return true;
      }
      await sleep(CREATE_INTERVAL_MS);
    }

    return false;
  }

  /**
   * Items keep being created while a rotation lands. Each one the server took has to end up
   * readable under the new key: the rotation carried it, or the server refused it for its key.
   *
   *   creators ──create──create──create──create──✗ refused
   *                             │
   *   rotator  ─────────────── rotate (retried while new items keep arriving) ──▶ K2
   */
  it(
    "keeps every item created while a rotation lands readable under the new key",
    async () => {
      const account = targetAccount(harness, V2_VECTOR);
      const rotator = await session(account);
      await ensureVaultNotEmpty(rotator);
      const creators = await sessions(account, CREATOR_COUNT);

      // 1. Every creator creates items until one is refused. The rotation waits for a few first.
      const created: CipherView[] = [];
      const creating = Promise.all(creators.map((client) => createUntilRefused(client, created)));
      while (created.length < CREATOR_COUNT) {
        await sleep(CREATE_INTERVAL_MS);
      }

      // 2. Rotate meanwhile, retrying while new items make what the rotation read incomplete
      let rotated = false;
      for (let attempt = 0; attempt < MAX_ROTATION_ATTEMPTS && !rotated; attempt++) {
        await rotator.sync();
        rotated = await rotate(
          rotator.getPasswordManagerClient(),
          account.password,
          "CreateIfNeeded",
        ).then(
          () => true,
          () => false,
        );
      }
      expect(rotated).toBe(true);

      // 3. Verify every creator was refused once the key changed
      expect(await creating).toEqual(creators.map(() => true));

      // 4. Verify a client that logs in fresh holds every item the server took, readable
      const client = await session(account);
      const { successes, failures } = await client
        .getPasswordManagerClient()
        .vault()
        .ciphers()
        .get_all();
      expect(failures).toHaveLength(0);
      expect(successes.map((cipher) => cipher.id)).toEqual(
        expect.arrayContaining(created.map((cipher) => cipher.id)),
      );
    },
    TIMEOUT,
  );

  /**
   * The master-password unlock data in a sync names the user key it holds, so a client can tell
   * stale unlock data from current. After a rotation it names the new key.
   */
  it(
    "names the account's user key in the master-password unlock data it syncs",
    async () => {
      const account = targetAccount(harness, V2_VECTOR);
      const rotator = await session(account);

      // 1. Rotate
      await rotate(rotator.getPasswordManagerClient(), account.password, "CreateIfNeeded");

      // 2. Verify a fresh login's sync names the account's key in its unlock data
      const synced = (await session(account)).lastSync?.userDecryption;
      expect(synced?.userKeyId).toBeTruthy();
      expect(synced?.masterPasswordUnlock?.containedKeyId).toBe(synced?.userKeyId);
    },
    TIMEOUT,
  );
});
