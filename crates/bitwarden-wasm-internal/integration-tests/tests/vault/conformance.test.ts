// The vault's encryption *format*, and what an edit does to it.
//
// Whether a cipher comes out blob-sealed or legacy field-encrypted is decided by
// `should_use_blob_encryption` from the account's security state, and whether a keyless cipher gains a
// per-item key is decided by the `enableCipherKeyEncryption` flag. Both are account-wide behaviours a unit
// test on a single cipher would not catch, and both are asserted here on the ciphertext itself.
//
// The edit matrix is the part that matters most. Every distinct cipher shape in the committed vectors —
// keyless, per-item-keyed, blob-sealed — crossed with every attachment layout — none, V0, V1, V2 — is
// edited, synced back down, and re-decrypted. The combination matters because the layouts differ in
// *where* the key lives: a V0 attachment's contents sit under the user key, a V1's under the cipher key, a
// V2's under its own key. An edit re-encrypts the cipher, and if it mishandled any of those the file would
// become unreadable while the cipher itself still decrypted fine.
//
// This file asserts ciphertext shapes and IV freshness on purpose, so it is expected to break whenever the
// storage format changes.

import type { CipherView } from "@bitwarden/sdk-internal";

import { userVector } from "../test-vectors/load";
import { expectJsonEqual } from "../test-vectors/validate";
import {
  arrangeVault,
  attachmentCases,
  EDIT_MATRIX_VECTORS,
  featureFlags,
  FOLDER_VECTOR,
  normalisedByEdit,
  renameRequest,
  unlockForEncryption,
  users,
  VAULT_TIMEOUT,
  variantOf,
  vectorCases,
  type VaultHarness,
} from "./vault-support";

describe("vault encryption", () => {
  describe.each(vectorCases)("%s", (_name, vector) => {
    const isV2 = vector.account.securityVersion >= 2;

    it(
      `re-encrypts ciphers as ${isV2 ? "blobs" : "legacy fields"}, matching the account`,
      async () => {
        const client = await unlockForEncryption(vector);
        const ciphers = client.vault().ciphers();

        for (const item of vector.vault.ciphers) {
          const { cipher } = await ciphers.encrypt(item.decrypted);

          // `data` carries the sealed blob, so its presence is the same signal
          // `Cipher::is_blob_encrypted` uses.
          if (isV2) {
            expect(cipher.data).toBeTruthy();
            // A V2 account always keeps a per-item key.
            expect(cipher.key).toBeTruthy();
          } else {
            expect(cipher.data ?? null).toBeNull();
            // Legacy ciphers carry their fields individually, so the name is really encrypted.
            expect(cipher.name).toBeTruthy();
          }

          // The format the account produces must match the format it was recorded in, or the
          // vector and the client disagree about what this account is.
          expect(Boolean(cipher.data)).toBe(item.blobEncrypted);
        }
      },
      VAULT_TIMEOUT,
    );

    it(
      "produces different ciphertext each time, so IVs are never reused",
      async () => {
        const client = await unlockForEncryption(vector);
        const ciphers = client.vault().ciphers();
        const item = vector.vault.ciphers[0];

        const first = await ciphers.encrypt(item.decrypted);
        const second = await ciphers.encrypt(item.decrypted);

        // Whichever field carries the payload for this account's format must differ.
        const payload = (cipher: { data?: string | null; name?: unknown }) =>
          isV2 ? cipher.data : String(cipher.name);
        expect(payload(first.cipher)).not.toBe(payload(second.cipher));
      },
      VAULT_TIMEOUT,
    );

    it(
      "encrypts a list the same way it encrypts items one at a time",
      async () => {
        const client = await unlockForEncryption(vector);
        const ciphers = client.vault().ciphers();
        const views = vector.vault.ciphers.map((item) => item.decrypted);

        const encrypted = await ciphers.encrypt_list(views);
        expect(encrypted).toHaveLength(views.length);

        for (const [index, context] of encrypted.entries()) {
          expect(context.encryptedFor).toBe(vector.account.userId);
          expect(Boolean(context.cipher.data)).toBe(vector.vault.ciphers[index].blobEncrypted);

          const roundTripped = await ciphers.decrypt(context.cipher);
          expectJsonEqual(
            roundTripped,
            views[index],
            `${vector.name}: cipher ${vector.vault.ciphers[index].id} via encrypt_list`,
          );
        }
      },
      VAULT_TIMEOUT,
    );
  });
});

// `enableCipherKeyEncryption` decides whether `encrypt` mints a per-item key for a cipher that has
// none. It only has an observable effect on a V1 account: a V2 account's ciphers always carry a key
// already, so there is nothing for the flag to do.
describe("the enableCipherKeyEncryption flag", () => {
  // Mixed V1 vault, so it has a keyless cipher — and no attachments on it, which keeps this about
  // the flag rather than about attachment key rewrapping.
  const vector = userVector(users, "v1-argon2id-password");

  const keylessCipher = (): CipherView => {
    const item = vector.vault.ciphers.find((cipher) => cipher.keys.cipherKey === null);
    if (item === undefined) {
      throw new Error(`${vector.name} was expected to contain a keyless cipher`);
    }
    return item.decrypted;
  };

  it(
    "leaves a keyless cipher keyless when off",
    async () => {
      const client = await unlockForEncryption(
        vector,
        featureFlags({ enableCipherKeyEncryption: false }),
      );
      const ciphers = client.vault().ciphers();
      const view = keylessCipher();

      const { cipher } = await ciphers.encrypt(view);
      expect(cipher.key ?? null).toBeNull();

      expectJsonEqual(await ciphers.decrypt(cipher), view, `${vector.name}: keyless cipher`);
    },
    VAULT_TIMEOUT,
  );

  it(
    "mints a per-item key for a keyless cipher when on",
    async () => {
      const client = await unlockForEncryption(
        vector,
        featureFlags({ enableCipherKeyEncryption: true }),
      );
      const ciphers = client.vault().ciphers();
      const view = keylessCipher();

      const { cipher } = await ciphers.encrypt(view);
      expect(cipher.key).toBeTruthy();

      // The upgrade must not cost the contents: everything decrypts to the same view *except*
      // `key`, which is a passthrough field on `CipherView` and now carries the freshly minted
      // wrapped key where the original had none. Pinned to the new key rather than excluded, so a
      // change to any other field still fails.
      expectJsonEqual(
        await ciphers.decrypt(cipher),
        { ...view, key: cipher.key },
        `${vector.name}: upgraded cipher`,
      );
    },
    VAULT_TIMEOUT,
  );

  it(
    "leaves an already-keyed cipher's key alone",
    async () => {
      const client = await unlockForEncryption(
        vector,
        featureFlags({ enableCipherKeyEncryption: true }),
      );
      const ciphers = client.vault().ciphers();
      const item = vector.vault.ciphers.find((cipher) => cipher.keys.cipherKey !== null)!;

      const { cipher } = await ciphers.encrypt(item.decrypted);

      // `CipherView.key` is passed through as-is, so the wrapped key is the one the vector recorded.
      expect(String(cipher.key)).toBe(String(item.decrypted.key));
      expectJsonEqual(
        await ciphers.decrypt(cipher),
        item.decrypted,
        `${vector.name}: keyed cipher`,
      );
    },
    VAULT_TIMEOUT,
  );
});

describe("cipher CRUD", () => {
  let harness: VaultHarness;

  afterEach(() => harness.assertClean());

  // The requirement: every cipher shape and every attachment layout must still decrypt after an edit.
  describe.each(EDIT_MATRIX_VECTORS.map((name) => [name, userVector(users, name)] as const))(
    "editing %s",
    (_name, vector) => {
      it.each(vector.vault.ciphers.map((item) => [variantOf(item), item] as const))(
        "keeps a %s decryptable",
        async (_variant, item) => {
          // Arrange
          harness = await arrangeVault(vector);
          const { client, local } = harness;
          const ciphers = client.vault().ciphers();
          const before: CipherView = await ciphers.decrypt(item.encrypted);
          expectJsonEqual(before, item.decrypted, `${item.id} before edit`);

          // Act
          const edited = await ciphers.edit({
            ...renameRequest(before, `${before.name} (edited)`),
            favorite: !before.favorite,
          });

          // Assert
          await harness.assertAccountIntact({
            expect: {
              ciphers: {
                [item.id]: {
                  name: `${before.name} (edited)`,
                  favorite: !before.favorite,
                  ...normalisedByEdit(before, item),
                },
              },
            },
          });
          // Specific to this test: the edit returned what it stored, and the attachment keys came
          // through untouched — a V2 attachment still exposes the recorded key, a V0/V1 one still
          // exposes none.
          expect(edited.name).toBe(`${before.name} (edited)`);
          const after = await ciphers.decrypt((await local.ciphers.get(item.id))!);
          for (const attachment of after.attachments ?? []) {
            const recorded = item.keys.attachments[attachment.id!];
            expect(recorded).toBeDefined();
            if (recorded.version === "V2") {
              expect((attachment as { decryptedKey?: string }).decryptedKey).toBe(recorded.key);
            } else {
              expect((attachment as { decryptedKey?: string }).decryptedKey ?? null).toBeNull();
            }
          }
          expect(after.attachments ?? []).toHaveLength(Object.keys(item.keys.attachments).length);
        },
        VAULT_TIMEOUT,
      );
    },
  );
});

describe("folder CRUD", () => {
  let harness: VaultHarness;

  afterEach(() => harness.assertClean());

  it(
    "decrypt_list agrees with decrypting each folder individually",
    async () => {
      // Arrange
      harness = await arrangeVault(FOLDER_VECTOR);
      const { client, local } = harness;
      const folders = client.vault().folders();
      const stored = local.folders.dump();

      // Act
      const batch = folders.decrypt_list(stored);

      // Assert
      await harness.assertAccountIntact();
      // Specific to this test: the batch path is a different implementation from the single one, so
      // every item must match what decrypting it alone produces.
      expect(batch).toHaveLength(stored.length);
      for (const [index, item] of stored.entries()) {
        expectJsonEqual(
          batch[index],
          folders.decrypt(item),
          `folder ${(item as any).id} batch vs single`,
        );
      }
    },
    VAULT_TIMEOUT,
  );
});

it("covers every distinct cipher and attachment variant in the vector set", () => {
  // Guards the matrix above: if a regenerated vector set adds a shape, it must be covered here too.
  const covered = new Set(
    EDIT_MATRIX_VECTORS.flatMap((name) => userVector(users, name).vault.ciphers.map(variantOf)),
  );
  const all = new Set(users.flatMap((vector) => vector.vault.ciphers.map(variantOf)));
  expect([...all].sort().filter((variant) => !covered.has(variant))).toEqual([]);
});

it("covers all three attachment layouts", () => {
  const versions = new Set(attachmentCases.map(([, , , , keys]) => keys.version));
  expect([...versions].sort()).toEqual(["V0", "V1", "V2"]);
});
