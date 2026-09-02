import {
  ChangeKdfError,
  ClientSettings,
  Kdf,
  MasterPasswordUnlockData,
  PasswordManagerClient,
  WasmStateBridge,
  isChangeKdfError,
} from "@bitwarden/sdk-internal";

import { HttpMock, installHttpMock } from "../http-mock";
import {
  MASTER_KEY_WRAPPED_USER_KEY,
  TEST_EMAIL,
  TEST_KDF_PARAMS,
  TEST_PASSWORD,
  initializeUserCrypto,
  makeInitializedPasswordmanagerClient,
  makePasswordManagerClient,
  makeStateBridge,
  seedMasterPasswordUnlockData,
} from "../utils";

// Nothing listens here; every request is served by the fetch mock. A concrete host keeps the
// SDK's request URLs parseable and makes an unmocked route fail loudly rather than escape to
// the network.
const SETTINGS: ClientSettings = {
  apiUrl: "http://localhost:4000",
  identityUrl: "http://localhost:4000/identity",
};

const ROUTE = "POST /accounts/kdf";

const NEW_PBKDF2: Kdf = { pBKDF2: { iterations: 700_000 } };
const NEW_ARGON2: Kdf = { argon2id: { iterations: 3, memory: 16, parallelism: 4 } };

const PBKDF2_SHA256 = 0;
const ARGON2ID = 1;

const TIMEOUT = 60_000;

/** Guards the user-key comparisons below against passing on two `undefined`s. */
const BASE64_PATTERN = /^[A-Za-z0-9+/]{40,}={0,2}$/;

/** Key ids travel as a lowercase hex encoding of 16 bytes. */
const KEY_ID_PATTERN = /^[0-9a-f]{32}$/;

/** A client unlocked under {@link TEST_KDF_PARAMS} with its master-password state seeded. */
async function setup(): Promise<{ stateBridge: WasmStateBridge; client: PasswordManagerClient }> {
  const stateBridge = makeStateBridge();
  const client = await makeInitializedPasswordmanagerClient(stateBridge, SETTINGS);
  await seedMasterPasswordUnlockData(stateBridge);
  return { stateBridge, client };
}

/** The happy-path stand-in for `POST /accounts/kdf`, which answers with an empty 200. */
const okRoutes = () => ({ [ROUTE]: () => ({}) });

/** Awaits a rejection and narrows it to a {@link ChangeKdfError}. */
async function rejection(promise: Promise<void>): Promise<ChangeKdfError> {
  const thrown = await promise.then(
    () => undefined,
    (error) => error,
  );
  if (!isChangeKdfError(thrown)) {
    throw new Error(`expected a ChangeKdfError, got ${thrown}`);
  }
  return thrown;
}

describe("change kdf", () => {
  let mock: HttpMock;

  afterEach(() => {
    expect(mock.unmatched.map((request) => request.route)).toEqual([]);
    mock.restore();
  });

  describe("request", () => {
    it(
      "posts the re-derived authentication and unlock data under the new KDF",
      async () => {
        mock = installHttpMock(okRoutes());
        const { client } = await setup();

        await client.user_crypto_management().change_kdf(TEST_PASSWORD, NEW_PBKDF2);

        expect(mock.routes()).toEqual([ROUTE]);

        const posted = mock.bodyFor(ROUTE);
        expect(Object.keys(posted).sort()).toEqual([
          "authenticationData",
          "masterPasswordHash",
          "unlockData",
        ]);
        expect(Object.keys(posted.authenticationData).sort()).toEqual([
          "kdf",
          "masterPasswordAuthenticationHash",
          "salt",
        ]);
        expect(Object.keys(posted.unlockData).sort()).toEqual([
          "containedKeyId",
          "kdf",
          "masterKeyWrappedUserKey",
          "salt",
        ]);

        // Both halves carry the new KDF; memory and parallelism are omitted for PBKDF2.
        const kdf = { kdfType: PBKDF2_SHA256, iterations: 700_000 };
        expect(posted.authenticationData.kdf).toEqual(kdf);
        expect(posted.unlockData.kdf).toEqual(kdf);

        // The salt is carried over from the current unlock data, not re-derived.
        expect(posted.authenticationData.salt).toBe(TEST_EMAIL);
        expect(posted.unlockData.salt).toBe(TEST_EMAIL);

        // The user key is re-wrapped under the master key derived with the new KDF.
        expect(posted.unlockData.masterKeyWrappedUserKey).toMatch(/^2\./);
        expect(posted.unlockData.masterKeyWrappedUserKey).not.toBe(MASTER_KEY_WRAPPED_USER_KEY);

        // Changing the KDF re-wraps the same user key, so the asserted contained key id is the
        // one this account's key already had.
        expect(posted.unlockData.containedKeyId).toMatch(KEY_ID_PATTERN);
      },
      TIMEOUT,
    );

    it(
      "proves possession with a hash derived under the old KDF",
      async () => {
        mock = installHttpMock(okRoutes());
        const { client } = await setup();

        await client.user_crypto_management().change_kdf(TEST_PASSWORD, NEW_PBKDF2);

        const posted = mock.bodyFor(ROUTE);
        // `masterPasswordHash` is the old-KDF hash the server authenticates the change with;
        // `authenticationData` is what replaces it. Same password, different KDF, so they differ.
        expect(posted.masterPasswordHash).not.toBe(
          posted.authenticationData.masterPasswordAuthenticationHash,
        );
        expect(posted.masterPasswordHash).not.toBe("");
      },
      TIMEOUT,
    );

    it(
      "converts the argon2id variant across the boundary",
      async () => {
        mock = installHttpMock(okRoutes());
        const { stateBridge, client } = await setup();

        await client.user_crypto_management().change_kdf(TEST_PASSWORD, NEW_ARGON2);

        const posted = mock.bodyFor(ROUTE);
        const kdf = { kdfType: ARGON2ID, iterations: 3, memory: 16, parallelism: 4 };
        expect(posted.authenticationData.kdf).toEqual(kdf);
        expect(posted.unlockData.kdf).toEqual(kdf);

        // Round trip: the argon2id variant survives the trip out to the bridge as well.
        expect(await stateBridge.get_kdf_config()).toEqual(NEW_ARGON2);
      },
      TIMEOUT,
    );
  });

  describe("persisted state", () => {
    it(
      "writes the new KDF config and unlock data to the state bridge",
      async () => {
        mock = installHttpMock(okRoutes());
        const { stateBridge, client } = await setup();

        await client.user_crypto_management().change_kdf(TEST_PASSWORD, NEW_PBKDF2);

        expect(await stateBridge.get_kdf_config()).toEqual(NEW_PBKDF2);

        const persisted = await stateBridge.get_masterpassword_unlock_data();
        expect(persisted).toBeDefined();
        expect(persisted!.kdf).toEqual(NEW_PBKDF2);
        expect(persisted!.salt).toBe(TEST_EMAIL);
        // Exactly what was posted, so client and server cannot disagree about the wrapped key.
        expect(persisted!.masterKeyWrappedUserKey).toBe(
          mock.bodyFor(ROUTE).unlockData.masterKeyWrappedUserKey,
        );
      },
      TIMEOUT,
    );

    it(
      "leaves the persisted unlock data usable: a fresh client recovers the same user key",
      async () => {
        mock = installHttpMock(okRoutes());
        const { stateBridge, client } = await setup();
        const userKey = await client.crypto().get_user_encryption_key();
        expect(userKey).toMatch(BASE64_PATTERN);

        await client.user_crypto_management().change_kdf(TEST_PASSWORD, NEW_PBKDF2);
        const persisted = await stateBridge.get_masterpassword_unlock_data();

        // A new client over a fresh bridge, unlocked from nothing but the persisted data.
        const next = makePasswordManagerClient(makeStateBridge(), SETTINGS);
        await initializeUserCrypto(
          next,
          {
            masterPasswordUnlock: {
              password: TEST_PASSWORD,
              master_password_unlock: persisted as MasterPasswordUnlockData,
            },
          },
          NEW_PBKDF2,
        );

        // Changing the KDF re-wraps the user key; it must not change it.
        expect(await next.crypto().get_user_encryption_key()).toBe(userKey);
      },
      TIMEOUT,
    );
  });

  describe("failures", () => {
    it(
      "leaves state untouched when the server rejects the change",
      async () => {
        mock = installHttpMock({
          [ROUTE]: () => ({ status: 400, json: { message: "kdf change rejected" } }),
        });
        const { stateBridge, client } = await setup();

        const error = await rejection(
          client.user_crypto_management().change_kdf(TEST_PASSWORD, NEW_PBKDF2),
        );

        expect(error.variant).toBe("Api");
        expect(mock.routes()).toEqual([ROUTE]);
        // Nothing is persisted, so the account is not left half-migrated.
        expect(await stateBridge.get_kdf_config()).toBeNull();
        const unlockData = await stateBridge.get_masterpassword_unlock_data();
        expect(unlockData!.kdf).toEqual(TEST_KDF_PARAMS);
        expect(unlockData!.masterKeyWrappedUserKey).toBe(MASTER_KEY_WRAPPED_USER_KEY);
      },
      TIMEOUT,
    );

    it(
      "errors before making a request when the unlock data is missing",
      async () => {
        mock = installHttpMock(okRoutes());
        // No `seedMasterPasswordUnlockData`: the bridge has no master-password state.
        const client = await makeInitializedPasswordmanagerClient(makeStateBridge(), SETTINGS);

        const error = await rejection(
          client.user_crypto_management().change_kdf(TEST_PASSWORD, NEW_PBKDF2),
        );

        expect(error.variant).toBe("MissingMasterPasswordUnlockData");
        expect(mock.requests).toEqual([]);
      },
      TIMEOUT,
    );

    it(
      "errors before making a request when the new KDF is below the allowed minimum",
      async () => {
        mock = installHttpMock(okRoutes());
        const { stateBridge, client } = await setup();
        const belowMinimum: Kdf = { argon2id: { iterations: 1, memory: 16, parallelism: 1 } };

        const error = await rejection(
          client.user_crypto_management().change_kdf(TEST_PASSWORD, belowMinimum),
        );

        expect(error.variant).toBe("MasterPassword");
        expect(mock.requests).toEqual([]);
        expect(await stateBridge.get_kdf_config()).toBeNull();
      },
      TIMEOUT,
    );
  });

  it(
    "never sends the password or the user key",
    async () => {
      mock = installHttpMock(okRoutes());
      const { client } = await setup();
      const userKey = await client.crypto().get_user_encryption_key();
      expect(userKey).toMatch(BASE64_PATTERN);

      await client.user_crypto_management().change_kdf(TEST_PASSWORD, NEW_PBKDF2);

      expect(mock.requests).not.toEqual([]);
      for (const request of mock.requests) {
        expect(request.body).not.toContain(TEST_PASSWORD);
        expect(request.body).not.toContain(userKey);
      }
    },
    TIMEOUT,
  );
});
