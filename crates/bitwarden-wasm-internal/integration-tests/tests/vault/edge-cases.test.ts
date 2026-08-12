// Two vault cases worth pinning down so neither regresses: a write built on a stale revision, and
// attachment contents encrypted under a key that does not own them.

import { PureCrypto } from "@bitwarden/sdk-internal";

import { userVector } from "../test-vectors/load";
import { expectJsonEqual } from "../test-vectors/validate";
import {
  arrangeVault,
  attachmentCases,
  FILE_CONTENTS,
  normalisedByEdit,
  renameRequest,
  users,
  VAULT_TIMEOUT,
  type VaultHarness,
} from "./vault-support";

describe("cipher CRUD", () => {
  const vector = userVector(users, "v1-argon2id-password");

  let harness: VaultHarness;

  afterEach(() => harness.assertClean());

  it(
    "rejects a second edit made from a stale revision",
    async () => {
      // Optimistic concurrency: the client sends the revision it last saw, and the server refuses a
      // write built on an older one. Only testable because the model server advances revisions —
      // against a mock that echoed them back, both edits would succeed and the second would silently
      // clobber the first.

      // Arrange
      harness = await arrangeVault(vector);
      const { api, client } = harness;
      const item = vector.vault.ciphers[0];
      const ciphers = client.vault().ciphers();
      const stale = await ciphers.decrypt(item.encrypted);
      await ciphers.edit(renameRequest(stale, "First write"));
      const afterFirst = structuredClone(api.db.ciphers.get(item.id)!.cipher);

      // Act
      const second = ciphers.edit(renameRequest(stale, "Second write"));

      // Assert
      await expect(second).rejects.toBeDefined();
      await harness.assertAccountIntact({
        expect: {
          ciphers: { [item.id]: { name: "First write", ...normalisedByEdit(stale, item) } },
        },
      });
      // Specific to this test: the rejected write left the account byte-identical. Checking the name
      // alone would pass against a server that applied the write and merely reported the old name,
      // or that advanced the revision on a request it refused.
      expectJsonEqual(
        api.db.ciphers.get(item.id)?.cipher,
        afterFirst,
        `${item.id} unchanged by the rejected write`,
      );
    },
    VAULT_TIMEOUT,
  );
});

describe("attachment contents", () => {
  let harness: VaultHarness;

  afterEach(() => harness.assertClean());

  it(
    "refuses contents encrypted under the wrong key",
    async () => {
      // Proof the round trip in `happy-path.test.ts` has teeth: if `decrypt_buffer` ignored the
      // resolved content key, decrypting under an unrelated key would succeed.
      const [, attachmentVector, item, attachmentId] = attachmentCases[0];
      harness = await arrangeVault(attachmentVector);
      const { client } = harness;

      const view = await client.vault().ciphers().decrypt(item.encrypted);
      const attachmentView = (view.attachments ?? []).find((a) => a.id === attachmentId)!;

      const wrongKey = Buffer.from(PureCrypto.make_user_key_aes256_cbc_hmac());
      const encrypted = PureCrypto.symmetric_encrypt_filedata(FILE_CONTENTS, wrongKey);

      expect(() =>
        client.vault().attachments().decrypt_buffer(item.encrypted, attachmentView, encrypted),
      ).toThrow();
    },
    VAULT_TIMEOUT,
  );
});
