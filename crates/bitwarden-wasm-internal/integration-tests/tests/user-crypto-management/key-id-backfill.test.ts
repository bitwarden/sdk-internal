import { isKeyIdBackfillError } from "@bitwarden/sdk-internal";

import { LoginMethod, type ClientEmulator } from "../../client-emulator/client-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { asKeyId } from "../type-assertion-helpers";
import { loadUserVectors, userVector } from "../../vectors/load";
import { rejection } from "../utils";

/** A V2 account: its user key carries a key id the server has held all along. */
const V2_VECTOR = userVector(loadUserVectors(), "v2-pbkdf2-blob");
const V2_USER_KEY = V2_VECTOR.rawCryptographicState.userKey;

/** A V1 master-password account, whose user key carries no key id. */
const V1_VECTOR = userVector(loadUserVectors(), "v1-pbkdf2-min-iterations");

/** Key ids travel as a lowercase hex encoding of 16 bytes. */
const KEY_ID_PATTERN = /^[0-9a-f]{32}$/;

const TIMEOUT = 60_000;

describe("user key id backfill", () => {
  let harness: TestHarness;

  beforeEach(() => {
    harness = testHarness();
  });

  afterEach(() => harness.restore());

  /** Logs in and unlocks the V2 account, whose user key the vector records in the clear. */
  async function loginV2(): Promise<ClientEmulator> {
    const { email } = harness.server.seedUserTestVector(V2_VECTOR);

    const client = harness.newClientEmulator();
    await client.login(email, LoginMethod.ForceLogin);
    await client.unlockWithUserKey(V2_USER_KEY);

    return client;
  }

  /** Logs in and unlocks the V1 master-password account, whose user key carries no key id. */
  async function loginV1(): Promise<ClientEmulator> {
    const { email } = harness.server.seedUserTestVector(V1_VECTOR);

    const client = harness.newClientEmulator();
    await client.login(email, LoginMethod.Password, V1_VECTOR.account.password);
    await client.unlock(V1_VECTOR.account.password);

    return client;
  }

  describe("user_key_id_needs_backfill", () => {
    it(
      "is false once the sync carries a key id",
      async () => {
        // 1. Log in to a V2 account
        const client = await loginV2();

        // 2. Verify the sync brought the id down and nothing is outstanding
        expect(await client.bridge.get_user_key_id()).toEqual(
          asKeyId(String(V2_VECTOR.rawCryptographicState.userKeyId)),
        );
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
      "is true for a V1 account, whose user has not backfilled the key id to the server",
      async () => {
        // 1. Log in to a V1 account, which the server holds no key id for
        const client = await loginV1();
        expect(harness.server.getUser(V1_VECTOR.account.email).userKeyId).toBeUndefined();

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
    it(
      "records the user key id of a V1 account on the server",
      async () => {
        // 1. Log in to a V1 account, the only kind the server holds no key id for
        const client = await loginV1();
        const sdk = client.getPasswordManagerClient();

        // 2. Backfill the key id
        await sdk.user_crypto_management().user_key_id_backfill();

        // 3. Verify the server recorded the id the client holds
        const email = client.local.account.email;
        const recorded = harness.server.getUser(email).userKeyId;
        expect(recorded).toMatch(KEY_ID_PATTERN);
        expect(await client.bridge.get_user_key_id()).toEqual(recorded);

        // 4. Verify nothing is left to backfill, here and for a client that only syncs
        expect(await sdk.user_crypto_management().user_key_id_needs_backfill()).toBe(false);

        // 5. Verify a new client that only syncs sees the server's key id
        const returning = harness.newClientEmulator();
        await returning.login(email, LoginMethod.ForceLogin);
        expect(await returning.bridge.get_user_key_id()).toEqual(recorded);
      },
      TIMEOUT,
    );

    it(
      "changes nothing when the server rejects the key id",
      async () => {
        // 1. Log in to a V2 account, whose key id the server already holds and will not overwrite
        const client = await loginV2();

        // 2. Backfill the key id
        const error = await rejection(
          client.getPasswordManagerClient().user_crypto_management().user_key_id_backfill(),
          isKeyIdBackfillError,
        );

        // 3. Verify the request reached the server and was refused there
        expect(error.variant).toBe("Api");

        // 4. Verify neither side moved
        const recorded = asKeyId(String(V2_VECTOR.rawCryptographicState.userKeyId));
        expect(harness.server.getUser(V2_VECTOR.account.email).userKeyId).toEqual(recorded);
        expect(await client.bridge.get_user_key_id()).toEqual(recorded);
      },
      TIMEOUT,
    );
  });
});
