// Rotating the keys of a key-connector account, for each account version the vectors carry.
//
// A key-connector rotation authorizes itself with the key fetched from the connector rather than a
// derived master key, which is the one thing that differs from the other rotations. The shared
// assertion body lives in `tests/rotation-cases.ts`.

import type { InitUserCryptoMethod } from "@bitwarden/sdk-internal";

import { KEY_CONNECTOR_URL } from "../model-server/install";
import {
  assertRotationHarnessClean,
  expectRotationSucceeds,
  ROTATION_TIMEOUT,
  setupRotation,
  UNLOCK_METHOD,
  type RotationCase,
  type RotationHarness,
} from "../rotation-cases";
import { loadUserVectors, userVector, type UserVector } from "../test-vectors/load";

const users = loadUserVectors();

/** Pulls the key-connector key out of the vector's own key-connector unlock method. */
function keyConnectorKeyOf(vector: UserVector): string {
  const method = vector.unlockMethods.find((m) => "keyConnector" in m) as
    Extract<InitUserCryptoMethod, { keyConnector: unknown }> | undefined;
  if (method === undefined) {
    throw new Error(`${vector.name} has no key-connector unlock method`);
  }
  return method.keyConnector.master_key.toString();
}

const cases: [string, RotationCase][] = [
  [
    "V1 key connector",
    {
      vector: userVector(users, "v1-pbkdf2-key-connector"),
      method: () => ({ KeyConnector: { key_connector_url: KEY_CONNECTOR_URL } }),
      expectedUnlockMethod: UNLOCK_METHOD.keyConnector,
      keyConnectorKey: keyConnectorKeyOf(userVector(users, "v1-pbkdf2-key-connector")),
    },
  ],
  [
    "V2 key connector",
    {
      vector: userVector(users, "v2-pbkdf2-key-connector"),
      method: () => ({ KeyConnector: { key_connector_url: KEY_CONNECTOR_URL } }),
      expectedUnlockMethod: UNLOCK_METHOD.keyConnector,
      keyConnectorKey: keyConnectorKeyOf(userVector(users, "v2-pbkdf2-key-connector")),
    },
  ],
];

describe("key connector key rotation", () => {
  let harness: RotationHarness;

  afterEach(() => assertRotationHarnessClean(harness));

  describe.each(cases)("%s", (_label, rotationCase) => {
    it(
      "posts a V2 cryptographic state, the re-encrypted vault and the right unlock method",
      async () => {
        harness = setupRotation(rotationCase.vector, rotationCase.keyConnectorKey);
        await expectRotationSucceeds(harness, rotationCase);
      },
      ROTATION_TIMEOUT,
    );
  });
});
