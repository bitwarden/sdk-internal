// Decrypts every committed vector's vault, through every unlock method the vector declares.
//
// This is the baseline the rest of the suite rests on: if an account in the set cannot be opened and
// read end to end, nothing else that account appears in means anything. It matters in TypeScript
// rather than only in Rust because the models cross the FFI boundary on the way in and out — a
// `Cipher` is deserialized from JS, decrypted in Rust, and a `CipherView` is serialized back — so a
// naming or shape regression in the bindings shows up as a decryption mismatch the Rust tests would
// never see.

import { unlockMethodName } from "../test-vectors/load";
import { UNLOCK_TIMEOUT, validateVectorDirectly, vectorCases, vectors } from "./unlock-support";

describe("test vectors", () => {
  it("loads the expected set of vectors", () => {
    expect(vectors.map((vector) => vector.name).sort()).toEqual([
      "v1-argon2id-password",
      "v1-argon2id-tde",
      "v1-pbkdf2-key-connector",
      "v1-pbkdf2-min-iterations",
      "v1-pbkdf2-password",
      "v2-argon2id-blob",
      "v2-argon2id-tde",
      "v2-argon2id-upgrade-token",
      "v2-pbkdf2-blob",
      "v2-pbkdf2-key-connector",
    ]);
  });

  describe.each(vectorCases)("%s", (_name, vector) => {
    it.each(vector.unlockMethods.map((method) => [unlockMethodName(method), method] as const))(
      "decrypts its vault after unlocking via %s",
      async (_methodName, method) => {
        await validateVectorDirectly(vector, method);
      },
      UNLOCK_TIMEOUT,
    );
  });
});
