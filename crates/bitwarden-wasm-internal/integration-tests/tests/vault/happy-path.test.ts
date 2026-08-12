// The vault's basic functionality against the committed vectors: everything encrypts and decrypts back
// to what was recorded, and attachment contents come back byte for byte under every layout.
//
// Encryption is non-deterministic — fresh IVs and nonces every time — so there is nothing to compare the
// ciphertext against. What can be asserted is the round trip, which is what this file does; the *format*
// each account produces is asserted in `conformance.test.ts`.
//
// The attachment half matters because the vectors record attachment *keys* but not attachment *bytes*.
// `AttachmentFile::decrypt` resolves the content key differently per layout, and getting it wrong makes a
// file permanently unreadable while the cipher it hangs off still decrypts perfectly:
//
//   V0  no attachment key, cipher has no cipher key  -> contents under the user/organization key
//   V1  no attachment key, cipher *has* a cipher key -> contents still under the user/organization key
//   V2  attachment key present                       -> contents under that key, which is itself
//                                                       wrapped by the cipher key
//
// The V1 case is the subtle one: the legacy branch decrypts with the user/org slot, *not* with the cipher
// key it just unwrapped, even though the cipher has one. A refactor that "tidied" that to use
// `ciphers_key` would break every V1 attachment in existence, and every other test would still pass.
//
// Ciphertext is synthesised with `PureCrypto.symmetric_encrypt_filedata` under whichever key the layout
// says owns the contents, then handed to `decrypt_buffer`.

import { PureCrypto } from "@bitwarden/sdk-internal";

import { expectJsonEqual } from "../test-vectors/validate";
import {
  arrangeVault,
  attachmentCases,
  FILE_CONTENTS,
  FOLDER_VECTOR,
  unlockForEncryption,
  VAULT_TIMEOUT,
  vectorCases,
  type VaultHarness,
} from "./vault-support";

it("has folders to work with", () => {
  // The folder tests elsewhere would be vacuous against an empty vault.
  expect(FOLDER_VECTOR.vault.folders.length).toBeGreaterThan(0);
});

describe("vault encryption", () => {
  describe.each(vectorCases)("%s", (_name, vector) => {
    it(
      "round-trips every cipher through encrypt and back",
      async () => {
        const client = await unlockForEncryption(vector);
        const ciphers = client.vault().ciphers();

        for (const item of vector.vault.ciphers) {
          const { cipher, encryptedFor } = await ciphers.encrypt(item.decrypted);

          // The cipher is stamped with the user that encrypted it, not the one that owns it.
          expect(encryptedFor).toBe(vector.account.userId);

          const roundTripped = await ciphers.decrypt(cipher);
          expectJsonEqual(
            roundTripped,
            item.decrypted,
            `${vector.name}: cipher ${item.id} re-encrypted`,
          );
        }

        expect(vector.vault.ciphers.length).toBeGreaterThan(0);
      },
      VAULT_TIMEOUT,
    );

    if (vector.vault.folders.length > 0) {
      it(
        "round-trips every folder through encrypt and back",
        async () => {
          const client = await unlockForEncryption(vector);
          const folders = client.vault().folders();

          for (const item of vector.vault.folders) {
            const encrypted = folders.encrypt(item.decrypted);
            const roundTripped = folders.decrypt(encrypted);
            expectJsonEqual(
              roundTripped,
              item.decrypted,
              `${vector.name}: folder ${item.id} re-encrypted`,
            );

            // A folder is a single encrypted name, so a repeat encryption is the whole check.
            const again = folders.encrypt(item.decrypted);
            expect(String(encrypted.name)).not.toBe(String(again.name));
          }
        },
        VAULT_TIMEOUT,
      );
    }
  });
});

describe("attachment contents", () => {
  let harness: VaultHarness;

  afterEach(() => harness.assertClean());

  it.each(attachmentCases)(
    "decrypts a %s",
    async (_label, vector, item, attachmentId, keys) => {
      harness = await arrangeVault(vector);
      const { client } = harness;
      const attachments = client.vault().attachments();

      // The view carries the unwrapped attachment key, so it is also what tells us the SDK agrees with
      // the vector about which layout this is.
      const view = await client.vault().ciphers().decrypt(item.encrypted);
      const attachmentView = (view.attachments ?? []).find((a) => a.id === attachmentId);
      expect(attachmentView).toBeDefined();

      // Whichever key the layout says owns the contents.
      const contentKey =
        keys.version === "V2"
          ? Buffer.from(keys.key!, "base64")
          : Buffer.from(vector.rawCryptographicState.userKey, "base64");
      if (keys.version === "V2") {
        // The unwrapped key the SDK exposes must be the one the vector recorded, or the round trip
        // below would be testing the wrong key.
        expect((attachmentView as { decryptedKey?: string }).decryptedKey).toBe(keys.key);
      } else {
        expect((attachmentView as { decryptedKey?: string }).decryptedKey ?? null).toBeNull();
      }

      const encrypted = PureCrypto.symmetric_encrypt_filedata(FILE_CONTENTS, contentKey);
      const decrypted = attachments.decrypt_buffer(item.encrypted, attachmentView!, encrypted);

      expect(Buffer.from(decrypted)).toEqual(Buffer.from(FILE_CONTENTS));
    },
    VAULT_TIMEOUT,
  );
});

describe("folder CRUD", () => {
  let harness: VaultHarness;

  afterEach(() => harness.assertClean());

  it(
    "round-trips a folder through encrypt and decrypt",
    async () => {
      // Arrange
      harness = await arrangeVault(FOLDER_VECTOR);
      const folders = harness.client.vault().folders();
      const view = folders.decrypt(FOLDER_VECTOR.vault.folders[0].encrypted);

      // Act
      const reencrypted = folders.encrypt(view);

      // Assert
      await harness.assertAccountIntact();
      // Specific to this test: re-encrypting and decrypting again returns the same plaintext.
      expectJsonEqual(folders.decrypt(reencrypted), view, "folder re-encrypt round trip");
    },
    VAULT_TIMEOUT,
  );
});
