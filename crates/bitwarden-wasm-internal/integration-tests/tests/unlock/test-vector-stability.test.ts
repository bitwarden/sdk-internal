import type { InitUserCryptoMethod } from "@bitwarden/sdk-internal";

import { LoginMethod } from "../../client-emulator/client-emulator";
import { validateVault } from "../../client-emulator/validate";
import { testHarness } from "../../test-harness";
import { loadUserVectors, type UserVector } from "../../vectors/load";
import { testVectors } from "../../vectors/test-vectors";

const UNLOCK_TIMEOUT = 120_000;

const vectors = loadUserVectors();

/** Seeds `vector` into the server, syncs it down, unlocks with `method` and decrypts its vault. */
async function validateVector(vector: UserVector, method: InitUserCryptoMethod): Promise<void> {
  const harness = testHarness();

  try {
    const { email, seed } = harness.server.seedUserTestVector(vector);
    const client = harness.newClientEmulator();
    await client.login(email, LoginMethod.ForceLogin);
    await client.unlockWith(method);

    // Nothing has been written, so nothing may differ — not even the fields a write would restamp.
    await validateVault(client, seed, []);
  } finally {
    harness.restore();
  }
}

describe("test vectors", () => {
  /**
   * We provide indefinite support for these test vectors. Any regression here means we dropped
   * support for some account data. This requires an explicit discussion, and possibly customer
   * communication, if this is intended.
   */
  it("loads the expected set of vectors", () => {
    expect(vectors.map((vector) => vector.name).sort()).toEqual([
      "v1-argon2id-password",
      "v1-argon2id-tde",
      "v1-pbkdf2-key-connector",
      "v1-pbkdf2-min-iterations",
      "v1-pbkdf2-password",
      "v2-argon2id-blob",
      "v2-argon2id-tde",
      "v2-pbkdf2-blob",
      "v2-pbkdf2-key-connector",
    ]);
  });

  testVectors.eachUserAndUnlockMethod()(
    "%s decrypts its vault after unlocking via %s",
    async (_name, _methodName, vector, method) => {
      await validateVector(vector, method);
    },
    UNLOCK_TIMEOUT,
  );
});
