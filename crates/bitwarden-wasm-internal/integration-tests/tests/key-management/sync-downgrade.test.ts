// A sync must not be able to move a V2 account back to V1.

import type { PasswordManagerClient } from "@bitwarden/sdk-internal";

import type { ClientEmulator } from "../../client-emulator/client-emulator";
import { testHarness, type TestHarness } from "../../test-harness";
import { loadUserVectors, toSeedAccount, userVector } from "../../vectors/load";
import { asKeyId } from "../type-assertion-helpers";

const users = loadUserVectors();

const V2_VECTOR = userVector(users, "v2-pbkdf2-blob");
const V2_ACCOUNT = toSeedAccount(V2_VECTOR);
const V2_USER_KEY = V2_VECTOR.rawCryptographicState.userKey;

/** A real V1 state, for the server to try to hand a V2 account. */
const V1_STATE = userVector(users, "v1-pbkdf2-min-iterations").account.accountCryptographicState;

const TIMEOUT = 60_000;

const SERVER_KEY_ID = asKeyId("0f0e0d0c0b0a09080706050403020100");

describe("sync downgrade prevention", () => {
  let harness: TestHarness;
  let client: ClientEmulator;
  let passwordManagerClient: PasswordManagerClient;
  let email: string;

  beforeEach(async () => {
    harness = testHarness();
    email = harness.server.seedUser(V2_ACCOUNT).email;

    client = harness.newClientEmulator();
    await client.login(email);
    await client.unlockWithUserKey(V2_USER_KEY);
    passwordManagerClient = client.getPasswordManagerClient();
  }, TIMEOUT);

  afterEach(() => harness.restore());

  it(
    "keeps the V2 state when the server syncs a V1 state",
    async () => {
      const v2State = await client.bridge.get_account_cryptographic_state();

      // 1. The server starts reporting a V1 state for a V2 account
      const stored = harness.server.getUser(email);
      stored.accountCryptographicState = V1_STATE;
      stored.userKeyId = SERVER_KEY_ID;

      // 2. Sync
      await client.sync(email);

      // 3. Verify the downgrade was refused
      expect(await client.bridge.get_account_cryptographic_state()).toEqual(v2State);

      // 4. Verify the rest of the same payload still applied, so this is a refused downgrade and
      //    not a dropped sync
      expect(await client.bridge.get_user_key_id()).toEqual(SERVER_KEY_ID);
    },
    TIMEOUT,
  );

  it(
    "leaves the account able to unlock after a refused downgrade",
    async () => {
      const userKey = await passwordManagerClient.crypto().get_user_encryption_key();

      // 1. The server starts reporting a V1 state, and the client syncs it
      harness.server.getUser(email).accountCryptographicState = V1_STATE;
      await client.sync(email);

      // 2. Lock and reopen from the state the refusal left behind
      await client.lock();
      await client.unlockWithUserKey(V2_USER_KEY);

      // 3. Verify the account came back up on the same user key
      expect(await client.getPasswordManagerClient().crypto().get_user_encryption_key()).toBe(
        userKey,
      );
    },
    TIMEOUT,
  );
});
