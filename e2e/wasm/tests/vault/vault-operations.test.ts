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

const NEW_PASSWORD = "correct horse battery staple";

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
      password: NEW_PASSWORD,
      uris: [{ uri: "https://example.com" }],
    },
  },
  fields: [],
};

/** An edit request applying `changes` to the item the user opened, as the edit screen does. */
function editRequest(view: CipherView, changes: Partial<CipherEditRequest>): CipherEditRequest {
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
   *   client  ──create──▶ lock ─▶ unlock ─▶ reads
   *               │
   *   server  ────┴── stores ciphertext
   *               │
   *   relogin ────┴───── login ─▶ unlock ─▶ reads
   */
  testVectors.users.each(
    "$name creates a login",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const client = await open(seeded);

      // 1. Create
      const created = await client.getPasswordManagerClient().vault().ciphers().create(NEW_LOGIN);

      // 2. Verify the server holds ciphertext, not the plaintext
      const stored = harness.server.db.ciphers.get(String(created.id));
      expect(JSON.stringify(stored?.cipher)).not.toContain(NEW_PASSWORD);

      // 3. Verify local state
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

      // 1. Edit an item created in this session
      const created = await client.getPasswordManagerClient().vault().ciphers().create(NEW_LOGIN);
      const editedNew = await client
        .getPasswordManagerClient()
        .vault()
        .ciphers()
        .edit(
          editRequest(created, {
            name: "Example, renamed",
            favorite: true,
            type: { login: { ...created.login, password: "new password" } },
          }),
        );

      // 2. Edit an item the vector recorded
      const original = await client
        .getPasswordManagerClient()
        .vault()
        .ciphers()
        .get(asCipherId(seededLoginId(seeded)));
      const editedSeeded = await client
        .getPasswordManagerClient()
        .vault()
        .ciphers()
        .edit(editRequest(original, { notes: "edited by the vault e2e suite" }));

      // 3. Verify the edit landed, so the vault assertions below cannot pass on a no-op edit
      expect(editedSeeded.notes).not.toEqual(original.notes);

      // 4. Verify local state
      await relock(client, seeded);
      await assertVault(client, seeded, { written: [editedNew, editedSeeded] });

      // 5. Verify server state
      await assertVault(await open(seeded), seeded, { written: [editedNew, editedSeeded] });
    },
    TIMEOUT,
  );

  /**
   *   client  ──soft delete──────────────▶ restore
   *                  │                        │
   *   relogin ───────┴─ sees it in trash      │
   *                                           │
   *   relogin ────────────────────────────────┴─ sees the seeded vault
   */
  testVectors.users.each(
    "$name moves a login to the trash and restores it",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const client = await open(seeded);
      const id = asCipherId(seededLoginId(seeded));

      // 1. Soft delete
      await client.getPasswordManagerClient().vault().ciphers().soft_delete(id);

      // 2. Verify a fresh login sees it in the trash. Local state is not compared here: the SDK
      //    stamps its own `deletedDate` locally, which differs from the server's until a sync.
      const trashed = await (
        await open(seeded)
      )
        .getPasswordManagerClient()
        .vault()
        .ciphers()
        .get(id);
      expect(trashed.deletedDate).toBeDefined();

      // 3. Restore
      await client.getPasswordManagerClient().vault().ciphers().restore(id);

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

      // 2. Verify it is gone from local state and a fresh login
      await relock(client, seeded);
      await assertVault(client, seeded, { removed: [id] });
      await assertVault(await open(seeded), seeded, { removed: [id] });
    },
    TIMEOUT,
  );

  /**
   * Folders are created and renamed through the SDK, and items filed into them either one at a
   * time on create or in bulk with a move.
   */
  testVectors.users.each(
    "$name files logins into a folder",
    async (vector) => {
      const seeded = harness.server.seedUserTestVector(vector);
      const client = await open(seeded);
      const movedId = asCipherId(seededLoginId(seeded));

      // 1. Create a folder and rename it
      const folder = await client
        .getPasswordManagerClient()
        .vault()
        .folders()
        .create({ name: "Work" });
      const folderId = folder.id!;
      await client
        .getPasswordManagerClient()
        .vault()
        .folders()
        .edit(folderId, { name: "Work, renamed" });

      // 2. File a new login into it on create, and a seeded one with a move
      const filed = await client
        .getPasswordManagerClient()
        .vault()
        .ciphers()
        .create({ ...NEW_LOGIN, folderId });
      await client.getPasswordManagerClient().vault().ciphers().move_many([movedId], folderId);
      const moved = await client.getPasswordManagerClient().vault().ciphers().get(movedId);

      // 3. Verify the move landed, so the vault assertions below cannot pass on a no-op move
      expect(moved.folderId).toBe(folderId);

      // 4. Verify local state
      await relock(client, seeded);
      const localFolder = await client.getPasswordManagerClient().vault().folders().get(folderId);
      expect(localFolder.name).toBe("Work, renamed");
      await assertVault(client, seeded, { written: [filed, moved] });

      // 5. Verify server state
      const relogin = await open(seeded);
      const serverFolder = await relogin.getPasswordManagerClient().vault().folders().get(folderId);
      expect(serverFolder.name).toBe("Work, renamed");
      await assertVault(relogin, seeded, { written: [filed, moved] });

      // 6. Move the seeded login back out, and verify it matches the vector again
      await client.getPasswordManagerClient().vault().ciphers().move_many([movedId], undefined);
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
      const device1 = await open(seeded);
      const device2 = await open(seeded);
      const id = asCipherId(seededLoginId(seeded));

      // 1. Both devices open the item; the first edits it
      const staleOnDevice2 = await device2.getPasswordManagerClient().vault().ciphers().get(id);
      const openOnDevice1 = await device1.getPasswordManagerClient().vault().ciphers().get(id);
      const edited = await device1
        .getPasswordManagerClient()
        .vault()
        .ciphers()
        .edit(editRequest(openOnDevice1, { notes: "edited on device 1" }));

      // 2. Verify the second device's edit from what it holds is refused, and changed nothing
      const error = await rejection(
        device2
          .getPasswordManagerClient()
          .vault()
          .ciphers()
          .edit(editRequest(staleOnDevice2, { notes: "edited on device 2" })),
        isEditCipherError,
      );
      expect(error.variant).toBe("Api");
      await assertVault(await open(seeded), seeded, { written: [edited] });

      // 3. The second device syncs, sees the first device's edit, and edits on top of it
      await device2.sync();
      const syncedOnDevice2 = await device2.getPasswordManagerClient().vault().ciphers().get(id);
      expect(syncedOnDevice2.notes).toBe("edited on device 1");
      const editedAgain = await device2
        .getPasswordManagerClient()
        .vault()
        .ciphers()
        .edit(editRequest(syncedOnDevice2, { notes: "edited on device 2" }));

      // 4. Verify the first device sees the second edit after it syncs
      await device1.sync();
      await assertVault(device1, seeded, { written: [editedAgain] });
    },
    TIMEOUT,
  );
});
