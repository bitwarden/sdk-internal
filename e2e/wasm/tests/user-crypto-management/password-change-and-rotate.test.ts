import { isRotateUserKeysError, type B64, type SymmetricKey } from "@bitwarden/sdk-internal";

import { LoginMethod, type ClientEmulator } from "../../client-emulator/client-emulator";
import { IGNORED_FIELDS, validateVault } from "../../client-emulator/validate";
import type { SeededTestVector } from "../../server-emulator/server-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { testVectors } from "../../vectors/test-vectors";
import { rejection } from "../utils";
import { changePasswordAndRotate, rotateByPassword, type ForceUpgradeV2 } from "./rotate-helpers";

const TIMEOUT = 120_000;

const V1_VECTOR = testVectors.users.withMasterPassword().get("v1-pbkdf2-min-iterations");
const V2_VECTOR = testVectors.users.withMasterPassword().get("v2-pbkdf2-blob");

const NEW_PASSWORD = "a new password the rotation sets";

const ROTATED_FIELDS = [...IGNORED_FIELDS, "key"];

const V1_USER_KEY_BYTES = 64;

const isV1UserKey = (key: SymmetricKey | B64 | null) =>
  key !== null && Buffer.from(key as string, "base64").length === V1_USER_KEY_BYTES;

/**
 * A rotation bundled with a password change, for each user key version and upgrade choice.
 *
 *   client  ──unlock(P1, K1)──▶ change password + rotate ──▶ P2, K2
 *                                         │
 *   server  ─────────────────────── vault re-encrypted to K2
 *                                         │
 *   relogin ──────────────────────────────┴── login(P2) ─▶ unlock(K2) ──▶ reads
 *
 * - V1 with `force-upgrade-v2-encryption` off stays V1, so older devices that cannot read V2
 *   data keep working.
 * - V1 with the flag on moves to V2.
 * - V2 stays V2 either way: a user key never goes back to V1.
 */
describe("password change and rotate user keys", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  function assertVaultDecrypts(client: ClientEmulator, seeded: SeededTestVector): Promise<void> {
    return validateVault(client, seeded.seed, ROTATED_FIELDS);
  }

  const cases: {
    name: string;
    vector: typeof V1_VECTOR;
    forceUpgradeV2: ForceUpgradeV2;
    expectedVersion: "V1" | "V2";
  }[] = [
    {
      name: "keeps a V1 account on V1",
      vector: V1_VECTOR,
      forceUpgradeV2: "off",
      expectedVersion: "V1",
    },
    {
      name: "upgrades a V1 account to V2",
      vector: V1_VECTOR,
      forceUpgradeV2: "on",
      expectedVersion: "V2",
    },
    {
      name: "keeps a V2 account on V2",
      vector: V2_VECTOR,
      forceUpgradeV2: "off",
      expectedVersion: "V2",
    },
  ];

  for (const { name, vector, forceUpgradeV2, expectedVersion } of cases) {
    it(
      `${name} with force-upgrade-v2-encryption ${forceUpgradeV2}`,
      async () => {
        const seeded = harness.server.seedUserTestVector(vector);
        const client = harness.newClientEmulator();
        await client.login(seeded.email, LoginMethod.Password, vector.account.password);
        await client.unlock(vector.account.password);
        const oldUserKey = await client
          .getPasswordManagerClient()
          .crypto()
          .get_user_encryption_key();

        // 1. Change the password and rotate
        await changePasswordAndRotate(
          client.getPasswordManagerClient(),
          vector.account.password,
          NEW_PASSWORD,
          forceUpgradeV2,
        );

        // 2. Verify a fresh login with the new password reads the vault over a new user key of
        //    the expected version
        const reloginClient = harness.newClientEmulator();
        await reloginClient.login(seeded.email, LoginMethod.Password, NEW_PASSWORD);
        await reloginClient.unlock(NEW_PASSWORD);
        await assertVaultDecrypts(reloginClient, seeded);

        const newUserKey = await reloginClient
          .getPasswordManagerClient()
          .crypto()
          .get_user_encryption_key();
        expect(newUserKey).not.toEqual(oldUserKey);
        expect(isV1UserKey(newUserKey)).toBe(expectedVersion === "V1");
        expect(await reloginClient.bridge.get_account_cryptographic_state()).toHaveProperty(
          expectedVersion,
        );
        expect(harness.server.getUser(seeded.email).accountCryptographicState).toHaveProperty(
          expectedVersion,
        );
      },
      TIMEOUT,
    );
  }

  /**
   * A V1 account rotated without the upgrade survives being rotated again, each time staying V1.
   *
   *   K0 ──rotate(P1→P2)──▶ K1 ──rotate(P2→P1)──▶ K2 ──▶ V1, vault still decrypts
   */
  it(
    "keeps a V1 account on V1 across consecutive rotations",
    async () => {
      const seeded = harness.server.seedUserTestVector(V1_VECTOR);
      const passwords = [V1_VECTOR.account.password, NEW_PASSWORD, V1_VECTOR.account.password];

      for (let round = 0; round < passwords.length - 1; round++) {
        const client = harness.newClientEmulator();
        await client.login(seeded.email, LoginMethod.Password, passwords[round]);
        await client.unlock(passwords[round]);
        await changePasswordAndRotate(
          client.getPasswordManagerClient(),
          passwords[round],
          passwords[round + 1],
          "off",
        );
      }

      const reloginClient = harness.newClientEmulator();
      const finalPassword = passwords[passwords.length - 1];
      await reloginClient.login(seeded.email, LoginMethod.Password, finalPassword);
      await reloginClient.unlock(finalPassword);
      await assertVaultDecrypts(reloginClient, seeded);
      expect(await reloginClient.bridge.get_account_cryptographic_state()).toHaveProperty("V1");
    },
    TIMEOUT,
  );

  /**
   * A rotation without a password change posts a V2-only request, so it cannot keep a V1 account
   * on V1. It is refused before anything reaches the server.
   */
  it(
    "refuses to rotate a V1 account without a password change unless it upgrades",
    async () => {
      const seeded = harness.server.seedUserTestVector(V1_VECTOR);
      const client = harness.newClientEmulator();
      await client.login(seeded.email, LoginMethod.Password, V1_VECTOR.account.password);
      await client.unlock(V1_VECTOR.account.password);
      const stateBefore = structuredClone(
        harness.server.getUser(seeded.email).accountCryptographicState,
      );

      const error = await rejection(
        rotateByPassword(
          client.getPasswordManagerClient(),
          V1_VECTOR.account.password,
          "CreateIfNeeded",
          "off",
        ),
        isRotateUserKeysError,
      );

      expect(error.variant).toBe("UpgradeRequired");
      expect(harness.server.getUser(seeded.email).accountCryptographicState).toEqual(stateBefore);
    },
    TIMEOUT,
  );
});
