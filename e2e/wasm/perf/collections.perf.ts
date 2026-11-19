// Performance harness: encrypting and decrypting an organization's collections through the WASM
// boundary.
//
//   generate views ──► encrypt_list ──► Collection[] ──► decrypt_list_with_failures
//
// Both arrows are timed; the collections encrypted during setup are the input to the decrypt.
//
// Collections are encrypted with the organization key of the V1 organization account.
//
// Env:
//   PERF_COLLECTIONS  collections in the organization            (default 5000)
//   PERF_RUNS         timed runs                                 (default 5)
//   PERF_LABEL        writes perf/results/<label>/<task>.json when set

import { strictEqual } from "node:assert/strict";

import { CollectionType, type CollectionView } from "@bitwarden/sdk-internal";
import { test } from "vitest";

import { TEST_ORGANIZATION_ID } from "../tests/org-fixtures";
import { makeOrgInitializedClient, makeStateBridge } from "../tests/utils";

import { benchOptions, runOptions } from "./bench";

const COUNT = Number(process.env.PERF_COLLECTIONS ?? 5000);
const RUNS = Number(process.env.PERF_RUNS ?? 5);

/** Generates `count` shared collections, `collection_1` to `collection_<count>`. */
function generateCollections(count: number): CollectionView[] {
  return Array.from({ length: count }, (_, i) => ({
    id: undefined,
    organizationId: TEST_ORGANIZATION_ID,
    name: `collection_${i + 1}`,
    externalId: undefined,
    hidePasswords: false,
    readOnly: false,
    manage: false,
    type: CollectionType.SharedCollection,
  }));
}

test("collections", async ({ bench }) => {
  // Client and collection setup is untimed.
  const client = await makeOrgInitializedClient(makeStateBridge());
  const collectionsClient = client.vault().collections();
  const views = generateCollections(COUNT);
  const collections = collectionsClient.encrypt_list(views);

  const encryptTask = "collections encrypt_list";
  const decryptTask = "collections decrypt_list_with_failures";

  // Assertions guard against silently measuring a failing encrypt or decrypt.
  await bench.compare(
    bench(encryptTask, benchOptions(encryptTask), () => {
      strictEqual(collectionsClient.encrypt_list(views).length, COUNT);
    }),
    bench(decryptTask, benchOptions(decryptTask), () => {
      const result = collectionsClient.decrypt_list_with_failures(collections);
      strictEqual(result.successes.length, COUNT);
    }),
    runOptions(`collections, ${COUNT} collections, ${RUNS} runs`, RUNS),
  );
});
