// Key rotation under contention. One suite, run against the emulator and against a live server:
// `rotate-concurrency.test.ts` and `rotate-concurrency.live.test.ts` each supply an account.

import type { CipherView } from "@bitwarden/sdk-internal";

import { LoginMethod, type ClientEmulator } from "../../client-emulator/client-emulator";
import { IGNORED_FIELDS, validateVault } from "../../client-emulator/validate";
import type { SeedVault } from "../../server-emulator/server-emulator";
import { rotateByPassword } from "./rotate-helpers";

const TIMEOUT = 600_000;

const ROTATED_FIELDS = [...IGNORED_FIELDS, "key"];

/** Clients racing to rotate the same account. */
const RACER_COUNT = 50;

/** Clients editing while a rotation happens. */
const EDITOR_COUNT = 5;

/** Edits every editor lands before the rotation starts, so there is something to lose. */
const WARMUP_EDITS = 3;

/** Pause between one editor's edits. Small, but not zero: a rotation needs a gap to fit in. */
const EDIT_INTERVAL_MS = 25;

/** Upper bound on edits per editor, so a server that never rejects fails the test, not hangs it. */
const MAX_EDITS = 5_000;

/** A rotation that read a vault an edit has since changed is refused and has to be retried. */
const MAX_ROTATION_ATTEMPTS = 100;

const PLACEHOLDER_NAME = "sdk-internal integration tests";

/** An account a suite can open any number of sessions on. */
export interface RotationAccount {
  email: string;
  password: string;
  newClient(): ClientEmulator;
}

/** An account the suite owns for the length of one test. */
export type AccountProvider = () => Promise<RotationAccount>;

/** A recorded vault, in the shape `validateVault` compares against. */
type Recorded = { vault: SeedVault };

export function rotationConcurrencySuite(provide: AccountProvider): void {
  /** A client logged in, synced and unlocked. */
  async function session(account: RotationAccount): Promise<ClientEmulator> {
    const client = account.newClient();
    await client.login(account.email, LoginMethod.Password, account.password);
    await client.unlock(account.password);

    return client;
  }

  /** Same as {@link session}, for many clients at once. Sequential: logins are not the test. */
  async function sessions(account: RotationAccount, count: number): Promise<ClientEmulator[]> {
    const clients: ClientEmulator[] = [];
    for (let i = 0; i < count; i++) {
      clients.push(await session(account));
    }

    return clients;
  }

  /** Gives the account something to rotate; a rotation over an empty vault proves nothing. */
  async function ensureVaultNotEmpty(client: ClientEmulator): Promise<void> {
    const sdk = client.getPasswordManagerClient();
    if ((await sdk.vault().ciphers().get_all()).successes.length > 0) {
      return;
    }

    await createLogin(client, PLACEHOLDER_NAME, "created by the rotation tests");
    await client.sync();
  }

  async function createLogin(
    client: ClientEmulator,
    name: string,
    notes: string,
  ): Promise<CipherView> {
    return await client
      .getPasswordManagerClient()
      .vault()
      .ciphers()
      .create({
        organizationId: undefined,
        collectionIds: [],
        folderId: undefined,
        name,
        notes,
        favorite: false,
        reprompt: 0,
        type: {
          login: {
            username: "integration-tests@example.com",
            password: "a password the rotation has to carry across",
            passwordRevisionDate: undefined,
            uris: undefined,
            totp: undefined,
            autofillOnPageLoad: undefined,
            fido2Credentials: undefined,
          },
        },
        fields: [],
      });
  }

  /** What the client's account decrypts to right now, in the shape a vector records. */
  async function record(client: ClientEmulator): Promise<Recorded> {
    const sdk = client.getPasswordManagerClient();

    const { successes, failures } = await sdk.vault().ciphers().get_all();
    if (failures.length > 0) {
      throw new Error(`${failures.length} cipher(s) failed to decrypt before the test began`);
    }

    const folders = await sdk.vault().folders().list();

    return {
      vault: {
        ciphers: client.local.ciphers.dump().map((encrypted) => ({
          id: String(encrypted.id),
          encrypted,
          decrypted: successes.find((cipher) => cipher.id === encrypted.id),
        })),
        folders: client.local.folders.dump().map((encrypted) => ({
          id: String(encrypted.id),
          encrypted,
          decrypted: folders.find((folder) => folder.id === encrypted.id),
        })),
      },
    };
  }

  /** The recorded vault plus items the test created, which the encrypted side does not matter for. */
  function withItems(recorded: Recorded, items: CipherView[]): Recorded {
    const added = items.map((decrypted) => ({
      id: String(decrypted.id),
      decrypted,
      // Only the decrypted side is compared.
      encrypted: undefined as never,
    }));

    return { vault: { ...recorded.vault, ciphers: [...(recorded.vault.ciphers ?? []), ...added] } };
  }

  /** Restarts a client's session onto whatever key the server holds now. */
  async function resync(client: ClientEmulator, password: string): Promise<void> {
    await client.sync();
    await client.lock();
    await client.unlock(password);
  }

  async function userKey(client: ClientEmulator): Promise<unknown> {
    return await client.getPasswordManagerClient().crypto().get_user_encryption_key();
  }

  /**
   * Many clients of one account try to rotate at once. Each read the same vault and key, so each
   * holds a valid-looking rotation, and only one may land.
   *
   *   client 1 ─┐
   *   client 2 ─┼─ rotate ─▶ server ──▶ one accepted, the rest refused, nothing half-written
   *   ...       │
   *   client 50 ┘
   */
  it(
    `lets exactly one of ${RACER_COUNT} concurrent rotations through`,
    async () => {
      const account = await provide();
      const racers = await sessions(account, RACER_COUNT);

      await ensureVaultNotEmpty(racers[0]);
      await racers[0].sync();
      const recorded = await record(racers[0]);
      const originalKey = await userKey(racers[0]);

      // 1. Everyone rotates at the same moment
      const outcomes = await Promise.allSettled(
        racers.map((racer) =>
          rotateByPassword(racer.getPasswordManagerClient(), account.password, "CreateIfNeeded"),
        ),
      );

      // 2. Verify exactly one got through
      const winners = outcomes.flatMap((outcome, index) =>
        outcome.status === "fulfilled" ? [index] : [],
      );
      expect(winners).toHaveLength(1);
      expect(outcomes.filter((outcome) => outcome.status === "rejected")).toHaveLength(
        RACER_COUNT - 1,
      );

      // 3. Verify the account holds the winner's rotation whole: a client that logs in fresh
      //    gets a key of its own, and the whole vault decrypts under it. A rotation that landed
      //    partly would leave items under a key the account no longer has.
      const fresh = await session(account);
      expect(await userKey(fresh)).not.toEqual(originalKey);
      await validateVault(fresh, recorded, ROTATED_FIELDS);

      // 4. Verify the winner agrees with what the server holds
      const winner = racers[winners[0]];
      await resync(winner, account.password);
      expect(await userKey(winner)).toEqual(await userKey(fresh));

      // 5. Verify a loser recovers with a resync, rather than being left unusable
      const loser = racers[winners[0] === 0 ? 1 : 0];
      await resync(loser, account.password);
      await validateVault(loser, recorded, ROTATED_FIELDS);
    },
    TIMEOUT,
  );

  /** What one editor did, as it wrote. */
  interface Editor {
    client: ClientEmulator;
    /** The last edit the server acknowledged. The vault has to end up holding exactly this. */
    acked: CipherView;
    ackedCount: number;
    /** Why the first refused edit was refused. Absent while edits still go through. */
    rejection?: unknown;
  }

  /** Edits one item until the server refuses, pausing between edits. */
  async function edit(editor: Editor): Promise<void> {
    for (let n = 1; n <= MAX_EDITS; n++) {
      const view = editor.acked;
      try {
        editor.acked = await editor.client
          .getPasswordManagerClient()
          .vault()
          .ciphers()
          .edit({
            id: view.id!,
            organizationId: view.organizationId,
            folderId: view.folderId,
            favorite: view.favorite,
            reprompt: view.reprompt,
            name: view.name,
            notes: `edit ${n}`,
            fields: view.fields ?? [],
            type: { login: view.login! },
            revisionDate: view.revisionDate,
            archivedDate: view.archivedDate,
            attachments: view.attachments ?? [],
            key: view.key,
          });
      } catch (error) {
        editor.rejection = error;
        return;
      }

      editor.ackedCount = n;
      await new Promise((resolve) => setTimeout(resolve, EDIT_INTERVAL_MS));
    }
  }

  /**
   * A rotation lands in the middle of a stream of edits. Edits made before it stay, and the rotation
   * has to account for them; edits made after it are refused, since they were encrypted under the
   * old key.
   *
   *   editors ──edit──edit──edit──edit──edit──edit──✗ refused
   *                         │
   *   rotator ───────────rotate (refused while it read stale data, retried) ──▶ new key
   */
  it(
    "rejects edits once a rotation lands, and keeps every edit before it",
    async () => {
      const account = await provide();
      const rotator = await session(account);
      await ensureVaultNotEmpty(rotator);
      await rotator.sync();
      const recorded = await record(rotator);
      const originalKey = await userKey(rotator);

      // 1. Every editor gets an item of its own, so edits never conflict with each other
      const editors: Editor[] = [];
      for (const client of await sessions(account, EDITOR_COUNT)) {
        const created = await createLogin(client, `editor ${editors.length}`, "edit 0");
        editors.push({ client, acked: created, ackedCount: 0 });
      }
      await rotator.sync();

      // 2. Editors edit flat out, while the rotator waits until they have all landed some edits
      const editing = Promise.all(editors.map(edit));
      while (editors.some((editor) => editor.ackedCount < WARMUP_EDITS)) {
        await new Promise((resolve) => setTimeout(resolve, EDIT_INTERVAL_MS));
      }

      // 3. Rotate, retrying while edits keep invalidating what the rotation read
      let rotated = false;
      for (let attempt = 1; attempt <= MAX_ROTATION_ATTEMPTS && !rotated; attempt++) {
        try {
          await rotateByPassword(
            rotator.getPasswordManagerClient(),
            account.password,
            "CreateIfNeeded",
          );
          rotated = true;
        } catch {
          // Refused: an edit changed the vault after the rotation read it. Read it again.
        }
      }
      expect(rotated).toBe(true);

      // 4. Verify edits start being refused, for every editor
      await editing;
      for (const editor of editors) {
        expect(editor.rejection).toBeDefined();
        expect(editor.ackedCount).toBeGreaterThanOrEqual(WARMUP_EDITS);
      }

      // 5. Verify every edit that was acknowledged is in the vault, and none that were not
      const expected = withItems(
        recorded,
        editors.map((editor) => editor.acked),
      );
      await resync(rotator, account.password);
      expect(await userKey(rotator)).not.toEqual(originalKey);
      await validateVault(rotator, expected, ROTATED_FIELDS);

      // 6. Verify each refused editor recovers with a sync, and reads the same vault
      for (const editor of editors) {
        await resync(editor.client, account.password);
        await validateVault(editor.client, expected, ROTATED_FIELDS);
      }

      // 7. Verify a client that logs in fresh reads it too
      await validateVault(await session(account), expected, ROTATED_FIELDS);
    },
    TIMEOUT,
  );
}
