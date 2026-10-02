import { isKeyIdBackfillError } from "@bitwarden/sdk-internal";

import type { ClientEmulator } from "../../client-emulator/client-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import {
  MASTER_PASSWORD_ACCOUNT,
  RECORDED_KEY_ID,
  V2_ACCOUNT,
  V2_ACCOUNT_WITH_RECORDED_KEY_ID,
} from "../../vectors/accounts";
import { rejection, TEST_EMAIL, TEST_PASSWORD } from "../utils";
import { V2_DECRYPTED_USER_KEY } from "../v2-fixtures";

/** Key ids travel as a lowercase hex encoding of 16 bytes. */
const KEY_ID_PATTERN = /^[0-9a-f]{32}$/;

const TIMEOUT = 60_000;

describe("user key id backfill", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  });

  afterEach(() => harness.restore());

  /** Logs in and unlocks the V2 account, which has no master password. */
  async function loginV2(vector = V2_ACCOUNT): Promise<ClientEmulator> {
    const { email } = harness.server.seedUser(vector);

    const client = harness.newClientEmulator();
    await client.login(email);
    await client.unlockWithUserKey(V2_DECRYPTED_USER_KEY);

    return client;
  }

  /** Logs in and unlocks the V1 master-password account, whose user key carries no key id. */
  async function loginV1(): Promise<ClientEmulator> {
    const { email } = harness.server.seedUser(MASTER_PASSWORD_ACCOUNT);

    const client = harness.newClientEmulator();
    await client.login(email);
    await client.unlock(TEST_PASSWORD);

    return client;
  }

  describe("user_key_id_needs_backfill", () => {
    it(
      "is true when the server has recorded no key id",
      async () => {
        // 1. Log in to an account the server holds no key id for
        const client = await loginV2();

        // 2. Verify a backfill is outstanding, and that answering said so from local state alone
        expect(
          await client
            .getPasswordManagerClient()
            .user_crypto_management()
            .user_key_id_needs_backfill(),
        ).toBe(true);
        expect(harness.server.getUser(TEST_EMAIL).userKeyId).toBeUndefined();
      },
      TIMEOUT,
    );

    it(
      "is false once the sync carries the server's key id",
      async () => {
        // 1. Log in to an account whose key id the server already recorded
        const client = await loginV2(V2_ACCOUNT_WITH_RECORDED_KEY_ID);

        // 2. Verify the sync brought the id down and nothing is outstanding
        expect(await client.bridge.get_user_key_id()).toEqual(RECORDED_KEY_ID);
        expect(
          await client
            .getPasswordManagerClient()
            .user_crypto_management()
            .user_key_id_needs_backfill(),
        ).toBe(false);
      },
      TIMEOUT,
    );

    it(
      "is true for a V1 account, whose user key derives a key id from its key material",
      async () => {
        // 1. Log in to a V1 account
        const client = await loginV1();

        // 2. Verify a backfill is outstanding
        expect(
          await client
            .getPasswordManagerClient()
            .user_crypto_management()
            .user_key_id_needs_backfill(),
        ).toBe(true);
      },
      TIMEOUT,
    );
  });

  describe("user_key_id_backfill", () => {
    it.each([
      { name: "a V2 account", login: () => loginV2() },
      { name: "a V1 account", login: () => loginV1() },
    ])(
      "records the user key id of $name on the server",
      async ({ login }) => {
        // 1. Log in to an account with no recorded key id
        const client = await login();
        const sdk = client.getPasswordManagerClient();

        // 2. Backfill the key id
        await sdk.user_crypto_management().user_key_id_backfill();

        // 3. Verify the server recorded the id the client holds
        const recorded = harness.server.getUser(TEST_EMAIL).userKeyId;
        expect(recorded).toMatch(KEY_ID_PATTERN);
        expect(await client.bridge.get_user_key_id()).toEqual(recorded);

        // 4. Verify nothing is left to backfill, here and for a client that only syncs
        expect(await sdk.user_crypto_management().user_key_id_needs_backfill()).toBe(false);

        // 5. Verify a new client that only syncs sees the server's key id
        const returning = harness.newClientEmulator();
        await returning.login(TEST_EMAIL);
        expect(await returning.bridge.get_user_key_id()).toEqual(recorded);
      },
      TIMEOUT,
    );

    it(
      "changes nothing when the server rejects the key id",
      async () => {
        // 1. Log in to an account whose key id the server already recorded, which it will not
        //    overwrite
        const client = await loginV2(V2_ACCOUNT_WITH_RECORDED_KEY_ID);

        // 2. Backfill the key id
        const error = await rejection(
          client.getPasswordManagerClient().user_crypto_management().user_key_id_backfill(),
          isKeyIdBackfillError,
        );

        // 3. Verify the request reached the server and was refused there
        expect(error.variant).toBe("Api");

        // 4. Verify neither side moved
        expect(harness.server.getUser(TEST_EMAIL).userKeyId).toEqual(RECORDED_KEY_ID);
        expect(await client.bridge.get_user_key_id()).toEqual(RECORDED_KEY_ID);
      },
      TIMEOUT,
    );
  });
});
