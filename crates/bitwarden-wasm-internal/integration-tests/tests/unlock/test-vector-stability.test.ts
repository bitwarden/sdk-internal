import { unlockCases } from "../../vectors/load";
import { UNLOCK_TIMEOUT, validateVector, vectors } from "./unlock-support";

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

  it.each(unlockCases(vectors))(
    "%s decrypts its vault after unlocking via %s",
    async (_name, _methodName, vector, method) => {
      await validateVector(vector, method);
    },
    UNLOCK_TIMEOUT,
  );
});
