// Rotating the keys of a trusted-device (TDE) account, for each account version the vectors carry.
//
// A TDE rotation authorizes itself with no user-supplied secret at all — the device is the credential.
// The shared assertion body lives in `tests/rotation-cases.ts`.

import {
  assertRotationHarnessClean,
  expectRotationSucceeds,
  ROTATION_TIMEOUT,
  setupRotation,
  UNLOCK_METHOD,
  type RotationCase,
  type RotationHarness,
} from "../rotation-cases";
import { loadUserVectors, userVector } from "../test-vectors/load";

const users = loadUserVectors();

const cases: [string, RotationCase][] = [
  [
    "V1 TDE",
    {
      vector: userVector(users, "v1-argon2id-tde"),
      method: () => "Tde",
      expectedUnlockMethod: UNLOCK_METHOD.tde,
    },
  ],
  [
    "V2 TDE",
    {
      vector: userVector(users, "v2-argon2id-tde"),
      method: () => "Tde",
      expectedUnlockMethod: UNLOCK_METHOD.tde,
    },
  ],
];

describe("trusted device key rotation", () => {
  let harness: RotationHarness;

  afterEach(() => assertRotationHarnessClean(harness));

  describe.each(cases)("%s", (_label, rotationCase) => {
    it(
      "posts a V2 cryptographic state, the re-encrypted vault and the right unlock method",
      async () => {
        harness = setupRotation(rotationCase.vector);
        await expectRotationSucceeds(harness, rotationCase);
      },
      ROTATION_TIMEOUT,
    );
  });
});
