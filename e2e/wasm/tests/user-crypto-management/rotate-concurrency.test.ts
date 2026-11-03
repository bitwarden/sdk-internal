import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import { rotationConcurrencySuite } from "./rotate-concurrency-suite";

const V2_VECTOR = testVectors.users.withMasterPassword().get("v2-pbkdf2-blob");

describe("rotate user keys under contention (emulator)", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  });

  afterEach(() => harness.restore());

  rotationConcurrencySuite(async () => {
    const seeded = harness.server.seedUserTestVector(V2_VECTOR);

    return {
      email: seeded.email,
      password: seeded.vector.account.password,
      newClient: () => harness.newClientEmulator(),
    };
  });
});
