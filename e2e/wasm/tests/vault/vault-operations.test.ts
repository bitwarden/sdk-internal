import {
  CipherRepromptType,
  isEditCipherError,
  type CipherCreateRequest,
  type CipherEditRequest,
  type CipherView,
} from "@bitwarden/sdk-internal";

import { LoginMethod, type ClientEmulator } from "../../client-emulator/client-emulator";
import { expectPlaintextEqual, IGNORED_FIELDS } from "../../client-emulator/validate";
import type { SeededTestVector } from "../../server-emulator/server-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { hasMasterPassword } from "../../vectors/load";
import { testVectors } from "../../vectors/test-vectors";
import { asCipherId } from "../type-assertion-helpers";
import { rejection } from "../utils";

const TIMEOUT = 120_000;

const V2_VECTOR = testVectors.users.withMasterPassword().get("v2-pbkdf2-blob");

/** A login as a user would fill one in. */
const NEW_LOGIN: CipherCreateRequest = {
  organizationId: undefined,
  collectionIds: [],
  folderId: undefined,
  name: "Example",
  notes: "created by the vault e2e suite",
  favorite: false,
  reprompt: CipherRepromptType.None,
  type: {
    login: {
      username: "alice@example.com",
      password: "correct horse battery staple",
      uris: [{ uri: "https://example.com" }],
    },
  },
  fields: [],
};

/** Applies the user's changes to the item they opened, as the edit screen does. */
function editOf(view: CipherView, changes: Partial<CipherEditRequest>): CipherEditRequest {
  if (view.id === undefined || view.login === undefined) {
    throw new Error(`cipher ${view.id} is not a saved login`);
  }

  return {
    id: view.id,
    organizationId: view.organizationId,
    folderId: view.folderId,
    favorite: view.favorite,
    reprompt: view.reprompt,
    name: view.name,
    notes: view.notes,
    fields: view.fields ?? [],
    type: { login: view.login },
    revisionDate: view.revisionDate,
    archivedDate: view.archivedDate,
    attachments: view.attachments ?? [],
    key: view.key,
    ...changes,
  };
}

/** The first seeded cipher without attachments, which every vector has. */
function seededLoginId(seeded: SeededTestVector): string {
  const found = (seeded.seed.vault?.ciphers ?? []).find(
    (cipher) => (cipher.decrypted?.attachments ?? []).length === 0,
  );
  if (found === undefined) {
    throw new Error(`${seeded.vector.name} records no cipher without attachments`);
  }

  return found.id;
}

describe("vault operations", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  /** Logs a new device in to `seeded` and unlocks it with the vector's first unlock method. */
  async function open(seeded: SeededTestVector): Promise<ClientEmulator> {
    const { email, vector } = seeded;
    const client = harness.newClientEmulator();

    // Only password login is implemented; TDE and Key Connector accounts skip authentication.
    if (hasMasterPassword(vector)) {
      await client.login(email, LoginMethod.Password, vector.account.password);
    } else {
      await client.login(email, LoginMethod.Unimplemented);
    }
    await client.unlockWith(vector.unlockMethods[0]);

    return client;
  }

  /** Locks `client` and unlocks it again, so reads come from local state rather than memory. */
  async function relock(client: ClientEmulator, seeded: SeededTestVector): Promise<void> {
    await client.lock();
    await client.unlockWith(seeded.vector.unlockMethods[0]);
  }

  /**
   * Asserts `client` decrypts exactly the seeded vault, with `written` items added or replacing the
   * seeded item of the same id, and `removed` ids gone.
   *
   * Every item is compared, so an operation on one item cannot pass by damaging another.
   */
  async function assertVault(
    client: ClientEmulator,
    seeded: SeededTestVector,
    changes: { written?: CipherView[]; removed?: string[] },
  ): Promise<void> {
    const expected = new Map(
      (seeded.seed.vault?.ciphers ?? []).map((cipher) => [cipher.id, cipher.decrypted]),
    );
    for (const id of changes.removed ?? []) {
      expected.delete(id);
    }
    for (const view of changes.written ?? []) {
      expected.set(String(view.id), view);
    }

    const result = await client.getPasswordManagerClient().vault().ciphers().get_all();
    expect(result.failures).toHaveLength(0);
    expect(result.successes.map((cipher) => String(cipher.id)).sort()).toEqual(
      [...expected.keys()].sort(),
    );

    for (const cipher of result.successes) {
      const id = String(cipher.id);
      expectPlaintextEqual(cipher, expected.get(id), `cipher ${id}`, IGNORED_FIELDS);
    }
  }

  /**
   *   client  ──create──▶ get ─▶ lock ─▶ unlock ─▶ reads
   *               │
   *   server  ────┴── stores ciphertext
   *               │
   *   relogin ────┴───────────── login ─▶ unlock ─▶ reads
   */
  testVectors.users.each(
    "$name creates a login",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const client = await open(seeded);

      // 1. Create
      const created = await client.getPasswordManagerClient().vault().ciphers().create(NEW_LOGIN);
      expect(created.id).toBeDefined();
      expect(created.name).toBe(NEW_LOGIN.name);
      expect(created.login?.password).toBe("correct horse battery staple");

      // 2. Verify the server holds ciphertext, not the plaintext
      const stored = harness.server.db.ciphers.get(String(created.id));
      expect(stored?.userId).toBe(seeded.userId);
      expect(JSON.stringify(stored?.cipher)).not.toContain("correct horse battery staple");

      // 3. Verify local state: get, then lock and unlock
      const fetched = await client
        .getPasswordManagerClient()
        .vault()
        .ciphers()
        .get(asCipherId(String(created.id)));
      expectPlaintextEqual(fetched, created, "created cipher");
      await relock(client, seeded);
      await assertVault(client, seeded, { written: [created] });

      // 4. Verify server state: a fresh login reads it
      await assertVault(await open(seeded), seeded, { written: [created] });
    },
    TIMEOUT,
  );

  /**
   * Edits both an item this session created and one the vector recorded, so the edit path runs
   * over every cipher format an account can hold, not just the one the SDK writes today.
   */
  testVectors.users.each(
    "$name edits a new and a seeded login",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const client = await open(seeded);
      const ciphers = () => client.getPasswordManagerClient().vault().ciphers();

      // 1. Edit an item created in this session
      const created = await ciphers().create(NEW_LOGIN);
      const editedNew = await ciphers().edit(
        editOf(created, {
          name: "Example, renamed",
          favorite: true,
          type: { login: { ...created.login, password: "new password" } },
        }),
      );
      expect(editedNew.name).toBe("Example, renamed");
      expect(editedNew.favorite).toBe(true);
      expect(editedNew.login?.password).toBe("new password");

      // 2. Edit an item the vector recorded
      const original = await ciphers().get(asCipherId(seededLoginId(seeded)));
      const editedSeeded = await ciphers().edit(
        editOf(original, { notes: "edited by the vault e2e suite" }),
      );
      expect(editedSeeded.notes).toBe("edited by the vault e2e suite");
      expect(editedSeeded.login?.password).toBe(original.login?.password);

      // 3. Verify local state
      await relock(client, seeded);
      await assertVault(client, seeded, { written: [editedNew, editedSeeded] });

      // 4. Verify server state
      await assertVault(await open(seeded), seeded, { written: [editedNew, editedSeeded] });
    },
    TIMEOUT,
  );

  /**
   *   client  ──soft delete──▶ in trash ──restore──▶ back in vault
   *                                │                    │
   *   relogin ─────────────────────┴─ sees trash        └─ sees vault
   */
  testVectors.users.each(
    "$name moves a login to the trash and restores it",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const client = await open(seeded);
      const ciphers = () => client.getPasswordManagerClient().vault().ciphers();
      const seededId = seededLoginId(seeded);
      const id = asCipherId(seededId);
      const original = await ciphers().get(id);

      // 1. Soft delete
      await ciphers().soft_delete(id);

      // 2. Verify both sides hold it in the trash, otherwise unchanged
      const trashed = await ciphers().get(id);
      expect(trashed.deletedDate).toBeDefined();
      expect(harness.server.db.ciphers.get(seededId)?.cipher.deletedDate).toBeDefined();
      expectPlaintextEqual(trashed, original, "trashed cipher", [...IGNORED_FIELDS, "deletedDate"]);

      const other = await open(seeded);
      const trashedOnServer = await other.getPasswordManagerClient().vault().ciphers().get(id);
      expect(trashedOnServer.deletedDate).toBeDefined();

      // 3. Restore
      const restored = await ciphers().restore(id);
      expect(restored.deletedDate).toBeUndefined();

      // 4. Verify both sides are back to the seeded vault
      await relock(client, seeded);
      await assertVault(client, seeded, {});
      await assertVault(await open(seeded), seeded, {});
    },
    TIMEOUT,
  );

  testVectors.users.each(
    "$name permanently deletes a login",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const client = await open(seeded);
      const id = seededLoginId(seeded);

      // 1. Delete
      await client.getPasswordManagerClient().vault().ciphers().delete(asCipherId(id));

      // 2. Verify it is gone from the server, local state, and a fresh login
      expect(harness.server.db.ciphers.get(id)).toBeUndefined();
      await relock(client, seeded);
      await assertVault(client, seeded, { removed: [id] });
      await assertVault(await open(seeded), seeded, { removed: [id] });
    },
    TIMEOUT,
  );

  /**
   * Folders are created and renamed through the SDK, and items filed into them either one at a
   * time on edit or in bulk with a move.
   */
  testVectors.users.each(
    "$name files logins into a folder",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const client = await open(seeded);
      const folders = () => client.getPasswordManagerClient().vault().folders();
      const ciphers = () => client.getPasswordManagerClient().vault().ciphers();
      const seededFolderCount = (seeded.seed.vault?.folders ?? []).length;

      // 1. Create a folder and rename it
      const created = await folders().create({ name: "Work" });
      expect(created.id).toBeDefined();
      const folderId = created.id!;
      const renamed = await folders().edit(folderId, { name: "Work, renamed" });
      expect(renamed.name).toBe("Work, renamed");

      // 2. File a new login into it on create, and a seeded one with a move
      const filed = await ciphers().create({ ...NEW_LOGIN, folderId });
      const movedId = asCipherId(seededLoginId(seeded));
      await ciphers().move_many([movedId], folderId);
      const moved = await ciphers().get(movedId);
      expect(moved.folderId).toBe(folderId);

      // 3. Verify local state
      await relock(client, seeded);
      expect(await folders().list()).toHaveLength(seededFolderCount + 1);
      expect((await folders().get(folderId)).name).toBe("Work, renamed");
      await assertVault(client, seeded, { written: [filed, moved] });

      // 4. Verify server state
      const other = await open(seeded);
      expect((await other.getPasswordManagerClient().vault().folders().get(folderId)).name).toBe(
        "Work, renamed",
      );
      await assertVault(other, seeded, { written: [filed, moved] });

      // 5. Move the seeded login back out, and verify it matches the vector again
      await ciphers().move_many([movedId], undefined);
      await relock(client, seeded);
      await assertVault(client, seeded, { written: [filed] });
      await assertVault(await open(seeded), seeded, { written: [filed] });
    },
    TIMEOUT,
  );

  /**
   * Two devices on one account. A sync is how the second learns of the first's write; until then,
   * an edit it makes from what it holds is stale, and the server refuses it.
   *
   *   device 1  ──edit ─────────────────────────────────────────────────────▶
   *                 │
   *   server    ────┴── revision R2 ─────────── 409 ──────────── R3
   *                                             │                 │
   *   device 2  ──(holds R1)──── edit from R1 ──┘ ─ sync ─ edit ──┘
   */
  it(
    "a second device picks up an edit on sync, and is refused an edit from stale data",
    async () => {
      const seeded = harness.server.seedUserTestVector(V2_VECTOR);
      const first = await open(seeded);
      const second = await open(seeded);
      const id = asCipherId(seededLoginId(seeded));
      const ciphersOf = (device: ClientEmulator) =>
        device.getPasswordManagerClient().vault().ciphers();

      // 1. Both devices open the item; the first edits it
      const stale = await ciphersOf(second).get(id);
      const edited = await ciphersOf(first).edit(
        editOf(await ciphersOf(first).get(id), { notes: "edited on device 1" }),
      );

      // 2. Verify the second device's edit from what it holds is refused, and changed nothing
      const error = await rejection(
        ciphersOf(second).edit(editOf(stale, { notes: "edited on device 2" })),
        isEditCipherError,
      );
      expect(error.variant).toBe("Api");
      await assertVault(await open(seeded), seeded, { written: [edited] });

      // 3. The second device syncs, sees the first device's edit, and edits on top of it
      await second.sync();
      const synced = await ciphersOf(second).get(id);
      expect(synced.notes).toBe("edited on device 1");
      const editedAgain = await ciphersOf(second).edit(
        editOf(synced, { notes: "edited on device 2" }),
      );

      // 4. Verify the first device sees the second edit after it syncs
      await first.sync();
      await assertVault(first, seeded, { written: [editedAgain] });
    },
    TIMEOUT,
  );
});
