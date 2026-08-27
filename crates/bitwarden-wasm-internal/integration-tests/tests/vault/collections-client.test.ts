import {
  Collection,
  CollectionId,
  CollectionType,
  OrganizationId,
  PasswordManagerClient,
} from "@bitwarden/sdk-internal";

import { TEST_ORGANIZATION_ID } from "../org-fixtures";
import { encstring, makeOrgInitializedClient, makeStateBridge } from "../utils";

// `decrypt_list_with_failures` is a thin FFI wrapper — its success/failure partitioning behavior
// is covered comprehensively by the crate's Rust unit tests (`CollectionsClient`). These
// integration tests exist only to prove the FFI-specific concern: that a failed item survives the
// WASM boundary as an untouched `Collection`, alongside successes, rather than aborting the batch.

function testCollection(overrides: Partial<Collection> = {}): Collection {
  return {
    id: "66c5ca57-0868-4c7e-902f-b181009709c0" as unknown as CollectionId,
    organizationId: TEST_ORGANIZATION_ID,
    name: encstring(
      "2.EI9Km5BfrIqBa1W+WCccfA==|laWxNnx+9H3MZww4zm7cBSLisjpi81zreaQntRhegVI=|x42+qKFf5ga6DIL0OW5pxCdLrC/gm8CXJvf3UASGteI=",
    ),
    externalId: undefined,
    hidePasswords: false,
    readOnly: false,
    manage: false,
    defaultUserCollectionEmail: undefined,
    type: CollectionType.SharedCollection,
    ...overrides,
  };
}

describe("CollectionsClient", () => {
  describe("decrypt_list_with_failures", () => {
    let client: PasswordManagerClient;

    beforeAll(async () => {
      client = await makeOrgInitializedClient(makeStateBridge());
    });

    it("returns every collection as a success when all decrypt", () => {
      const result = client.vault().collections().decrypt_list_with_failures([testCollection()]);

      expect(result.successes).toHaveLength(1);
      expect(result.failures).toHaveLength(0);
    });

    it("partitions successes and failures instead of aborting the whole batch", () => {
      const valid = testCollection();
      // No key for this organization exists in the key store, so decryption of this single item
      // must fail without affecting the others.
      const invalid = testCollection({
        id: "76c5ca57-0868-4c7e-902f-b181009709c1" as unknown as CollectionId,
        organizationId: "1c4d9d5a-0000-4000-8000-000000000000" as unknown as OrganizationId,
      });

      const result = client.vault().collections().decrypt_list_with_failures([valid, invalid]);

      expect(result.successes).toHaveLength(1);
      expect(result.failures).toHaveLength(1);
      // The failed item must cross the FFI boundary unchanged (still ciphertext) — decryption
      // failures must never leak partially-decrypted or plaintext data.
      expect(result.failures[0].id).toBe(invalid.id);
      expect(result.failures[0].name).toBe(invalid.name);
    });

    it("returns empty successes and failures for an empty list", () => {
      const result = client.vault().collections().decrypt_list_with_failures([]);

      expect(result.successes).toHaveLength(0);
      expect(result.failures).toHaveLength(0);
    });
  });
});
