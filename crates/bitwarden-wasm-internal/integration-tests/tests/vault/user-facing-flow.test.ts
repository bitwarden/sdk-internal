// The vault operations a user performs: add an item, rename it, delete and restore it, list what they
// have, and attach a file to something.
//
// These span all three layers at once — they encrypt, they call the API, and they write the result into a
// client-managed repository — so each one ends by asserting the account is still usable from both
// directions a real client can arrive from: lock then unlock on its own local state, and log out then log
// back in with nothing but what the server holds.

import { asCipherId } from "../type-assertion-helpers";
import type { CreateAttachmentRequest } from "@bitwarden/sdk-internal";

import { syncToLocalState, unlockMethodFor, validateLocalState } from "../model-server/sync";
import { expectCipherFromServer } from "../model-server/sync";
import { userVector, type CipherVectorItem } from "../test-vectors/load";
import { expectJsonEqual } from "../test-vectors/validate";
import {
  arrangeVault,
  FILE_CONTENTS,
  FOLDER_VECTOR,
  users,
  VAULT_TIMEOUT,
  type VaultHarness,
} from "./vault-support";

/** A mixed V1 vault with a cheap KDF: two ciphers, a folder and a send. */
const vector = userVector(users, "v1-argon2id-password");

describe("cipher CRUD", () => {
  let harness: VaultHarness;

  afterEach(() => harness.assertClean());

  describe("create, read, update, delete", () => {
    it(
      "creates a cipher",
      async () => {
        // Arrange
        harness = await arrangeVault(vector);

        // Act
        const created = await harness.client
          .vault()
          .ciphers()
          .create({
            organizationId: undefined,
            collectionIds: [],
            folderId: undefined,
            name: "Created Login",
            notes: "a note",
            favorite: true,
            reprompt: 0,
            type: {
              login: {
                username: "someone@example.com",
                password: "hunter2",
                passwordRevisionDate: undefined,
                uris: undefined,
                totp: undefined,
                autofillOnPageLoad: undefined,
                fido2Credentials: undefined,
              },
            },
            fields: [],
          });

        // Assert
        await harness.assertAccountIntact();
        // Specific to this test: the new cipher comes back off the server whole, and neither its name
        // nor its password is readable in what was stored.
        await expectCipherFromServer(
          harness.api,
          vector.account.email,
          String(created.id),
          created,
          "created cipher",
          { notInCiphertext: ["Created Login", "hunter2"] },
        );
      },
      VAULT_TIMEOUT,
    );

    it(
      "lists what local state holds",
      async () => {
        // Arrange
        harness = await arrangeVault(vector);
        const { client, local } = harness;

        // Act
        const listed = await client.vault().ciphers().list();

        // Assert
        await harness.assertAccountIntact();
        // Specific to this test: `list` agrees with decrypting local state directly, so it cannot have
        // reordered, deduplicated or dropped a field. Comparing names alone would not catch that.
        expect(listed.failures).toHaveLength(0);
        const byId = <T extends { id?: unknown }>(views: T[]) =>
          [...views].sort((a, b) => String(a.id).localeCompare(String(b.id)));
        expectJsonEqual(
          byId(listed.successes),
          byId(await client.vault().ciphers().decrypt_list(local.ciphers.dump())),
          "list vs decrypt_list of local state",
        );
        expect(listed.successes).toHaveLength(vector.vault.ciphers.length);
      },
      VAULT_TIMEOUT,
    );

    it(
      "soft deletes, then restores",
      async () => {
        // Arrange
        harness = await arrangeVault(vector);
        const { api, client, local } = harness;
        const item = vector.vault.ciphers[0];
        const ciphers = client.vault().ciphers();

        // Act
        await ciphers.soft_delete(asCipherId(item.id));
        await ciphers.restore(asCipherId(item.id));

        // Assert
        await harness.assertAccountIntact();
        // Specific to this test: the deletion marker is gone again on both sides.
        expect(((await local.ciphers.get(item.id)) as any).deletedDate ?? null).toBeNull();
        expect((api.db.ciphers.get(item.id)!.cipher as any).deletedDate ?? null).toBeNull();
      },
      VAULT_TIMEOUT,
    );

    it(
      "marks a soft-deleted cipher as deleted before it is restored",
      async () => {
        // Arrange
        harness = await arrangeVault(vector);
        const { api, client, local } = harness;
        const item = vector.vault.ciphers[0];

        // Act
        await client.vault().ciphers().soft_delete(asCipherId(item.id));

        // Assert
        // Not `assertAccountIntact`: a soft-deleted account is not the vector's account any more. The
        // vault must still decrypt, which is what validating the *stored* items shows.
        await syncToLocalState(api, vector.account.email, local);
        await validateLocalState(
          local,
          unlockMethodFor(api, vector.account.email),
          { ciphers: vector.vault.ciphers, folders: vector.vault.folders },
          { ignore: ["revisionDate", "key", "deletedDate"] },
        );
        // Specific to this test: both sides agree it is deleted.
        expect(((await local.ciphers.get(item.id)) as any).deletedDate).toBeTruthy();
        expect((api.db.ciphers.get(item.id)!.cipher as any).deletedDate).toBeTruthy();
      },
      VAULT_TIMEOUT,
    );

    it(
      "hard deletes a cipher",
      async () => {
        // Arrange
        harness = await arrangeVault(vector);
        const { api, client, local } = harness;
        const item = vector.vault.ciphers[0];

        // Act
        await client.vault().ciphers().delete(asCipherId(item.id));

        // Assert
        await syncToLocalState(api, vector.account.email, local);
        // Specific to this test: gone from local state and from the server, while everything else in
        // the vault still decrypts.
        expect(await local.ciphers.get(item.id)).toBeNull();
        expect(api.db.ciphers.get(item.id)).toBeUndefined();
        await validateLocalState(local, unlockMethodFor(api, vector.account.email), {
          ciphers: vector.vault.ciphers.filter((cipher) => cipher.id !== item.id),
          folders: vector.vault.folders,
        });
      },
      VAULT_TIMEOUT,
    );
  });
});

describe("folder CRUD", () => {
  let harness: VaultHarness;

  afterEach(() => harness.assertClean());

  it(
    "creates a folder",
    async () => {
      // Arrange
      harness = await arrangeVault(FOLDER_VECTOR);
      const { client, local } = harness;

      // Act
      const created = await client.vault().folders().create({ name: "Created Folder" });

      // Assert
      await harness.assertAccountIntact();
      // Specific to this test: the new folder is stored encrypted and reads back whole.
      const stored = await local.folders.get(String(created.id));
      expect(stored).not.toBeNull();
      expect(String((stored as any).name)).not.toBe("Created Folder");
      expect(String((stored as any).name)).toMatch(/^\d+\./);
      expectJsonEqual(
        client.vault().folders().decrypt(stored!),
        created,
        "created folder after sync",
      );
    },
    VAULT_TIMEOUT,
  );

  it(
    "renames a folder, advancing its revision but not its id",
    async () => {
      // Arrange
      harness = await arrangeVault(FOLDER_VECTOR);
      const { client } = harness;
      const item = FOLDER_VECTOR.vault.folders[0];
      const before = client.vault().folders().decrypt(item.encrypted);

      // Act
      const edited = await client
        .vault()
        .folders()
        .edit(item.id as never, { name: "Renamed" });

      // Assert
      await harness.assertAccountIntact({
        expect: { folders: { [item.id]: { name: "Renamed" } } },
      });
      // Specific to this test: the id is stable and the server stamped a fresh revision.
      expect(edited.id).toBe(item.id);
      expect(new Date(edited.revisionDate).getTime()).toBeGreaterThan(
        new Date(before.revisionDate).getTime(),
      );
    },
    VAULT_TIMEOUT,
  );

  it(
    "lists every folder in local state, decrypted",
    async () => {
      // Arrange
      harness = await arrangeVault(FOLDER_VECTOR);
      const { client, local } = harness;

      // Act
      const listed = await client.vault().folders().list();

      // Assert
      await harness.assertAccountIntact();
      // Specific to this test: `list` agrees with decrypting local state directly, so it cannot have
      // reordered, deduplicated or dropped a field. Comparing names alone would not catch that.
      const byId = <T extends { id?: unknown }>(views: T[]) =>
        [...views].sort((a, b) => String(a.id).localeCompare(String(b.id)));
      expectJsonEqual(
        byId(listed),
        byId(client.vault().folders().decrypt_list(local.folders.dump())),
        "list vs decrypt_list of local state",
      );
      expect(listed).toHaveLength(FOLDER_VECTOR.vault.folders.length);
    },
    VAULT_TIMEOUT,
  );
});

describe("attachment slot lifecycle", () => {
  const attachmentVector = userVector(users, "v2-argon2id-blob");
  /** The cipher in that vector that already has an attachment. */
  const item = attachmentVector.vault.ciphers.find(
    (cipher) => Object.keys(cipher.keys.attachments).length > 0,
  ) as CipherVectorItem;

  let harness: VaultHarness;

  afterEach(() => harness.assertClean());

  it(
    "creates a slot, then reads, renews and deletes it",
    async () => {
      harness = await arrangeVault(attachmentVector);
      const { api, client, local } = harness;
      const repository = local.ciphers;
      const attachments = client.vault().attachments();

      const view = await client.vault().ciphers().decrypt(item.encrypted);
      const existingCount = (view.attachments ?? []).length;
      expect(existingCount).toBeGreaterThan(0);

      // The key and file name are already-encrypted values; reuse the shapes the vector holds so the
      // request is well formed without inventing a new encryption here.
      const existing = (item.encrypted as any).attachments[0];
      const created = await attachments.create_attachment(asCipherId(item.id), {
        key: existing.key,
        fileName: existing.fileName,
        fileSize: FILE_CONTENTS.length,
        lastKnownRevisionDate: view.revisionDate,
        asAdmin: false,
      } satisfies CreateAttachmentRequest);

      expect(created.attachmentId).toBeTruthy();
      expect(created.uploadUrl).toContain(created.attachmentId);

      // The merged cipher is written back to the repository, with the new slot on it.
      const stored = (await repository.get(item.id)) as any;
      expect(stored.attachments).toHaveLength(existingCount + 1);
      // And the server holds the same count — local and remote agree.
      expect((api.db.ciphers.get(item.id)!.cipher as any).attachments).toHaveLength(
        existingCount + 1,
      );

      const downloadUrl = await attachments.get_attachment_download_url(
        asCipherId(item.id),
        created.attachmentId,
      );
      expect(downloadUrl).toContain(created.attachmentId);

      const renewed = await attachments.renew_file_upload_url(
        asCipherId(item.id),
        created.attachmentId,
      );
      expect(renewed).toContain("renewed");

      const afterDelete = await attachments.delete_attachment(
        asCipherId(item.id),
        created.attachmentId,
      );
      expect((afterDelete as any).attachments ?? []).toHaveLength(existingCount);
      const reread = (await repository.get(item.id)) as any;
      expect(reread.attachments ?? []).toHaveLength(existingCount);
      expect((api.db.ciphers.get(item.id)!.cipher as any).attachments ?? []).toHaveLength(
        existingCount,
      );
    },
    VAULT_TIMEOUT,
  );
});
