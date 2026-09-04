import {
  ClientSettings,
  KeyId,
  KeyIdBackfillError,
  ManagedSettingsClient,
  PasswordManagerClient,
  WasmStateBridge,
  init_sdk,
  isKeyIdBackfillError,
} from "@bitwarden/sdk-internal";

import { HttpMock, installHttpMock } from "../http-mock";
import {
  makeInitializedPasswordmanagerClient,
  makeStateBridge,
  makeV2AccountClient,
} from "../utils";

// Nothing listens here; every request is served by the fetch mock. A concrete host keeps the
// SDK's request URLs parseable and makes an unmocked route fail loudly rather than escape to
// the network.
const SETTINGS: ClientSettings = {
  apiUrl: "http://localhost:4000",
  identityUrl: "http://localhost:4000/identity",
};

const ROUTE = "POST /accounts/key-management/user-key-id";

/** Key ids travel as a lowercase hex encoding of 16 bytes. */
const KEY_ID_PATTERN = /^[0-9a-f]{32}$/;

/** Stands in for whatever id the server had already recorded. */
const RECORDED_KEY_ID = "000102030405060708090a0b0c0d0e0f" as unknown as KeyId;

const TIMEOUT = 60_000;

/** Awaits a rejection and narrows it to a {@link KeyIdBackfillError}. */
async function rejection(promise: Promise<unknown>): Promise<KeyIdBackfillError> {
  const thrown = await promise.then(
    () => undefined,
    (error) => error,
  );
  if (!isKeyIdBackfillError(thrown)) {
    throw new Error(`expected a KeyIdBackfillError, got ${thrown}`);
  }
  return thrown;
}

describe("user key id backfill", () => {
  let mock: HttpMock;
  let bridge: WasmStateBridge;

  beforeEach(() => {
    bridge = makeStateBridge();
  });

  afterEach(() => {
    expect(mock.unmatched.map((request) => request.route)).toEqual([]);
    mock.restore();
  });

  describe("user_key_id_needs_backfill", () => {
    it(
      "is true when the server has recorded no key id for a V2 account",
      async () => {
        mock = installHttpMock({});
        const client = await makeV2AccountClient(bridge, SETTINGS);

        expect(await client.user_crypto_management().user_key_id_needs_backfill()).toBe(true);
        // The check is answered from local state alone.
        expect(mock.routes()).toEqual([]);
      },
      TIMEOUT,
    );

    it(
      "is false once the server's key id is known",
      async () => {
        mock = installHttpMock({});
        const client = await makeV2AccountClient(bridge, SETTINGS);
        // Stands in for what the crypto sync handler stores when the server reports an id.
        await bridge.set_user_key_id(RECORDED_KEY_ID);

        expect(await client.user_crypto_management().user_key_id_needs_backfill()).toBe(false);
      },
      TIMEOUT,
    );

    it(
      "is true for a V1 account, whose user key derives a key id from its key material",
      async () => {
        mock = installHttpMock({});
        const client = await makeInitializedPasswordmanagerClient(bridge, SETTINGS);

        expect(await client.user_crypto_management().user_key_id_needs_backfill()).toBe(true);
        // The check is answered from local state alone.
        expect(mock.routes()).toEqual([]);
      },
      TIMEOUT,
    );

    it(
      "fails when the host registered no state bridge",
      async () => {
        mock = installHttpMock({});
        // Built without `makePasswordManagerClient`, which always registers a bridge. Without one
        // there is nowhere to read the server's key id from, so the answer is an error rather than
        // a guess.
        init_sdk();
        const client = new PasswordManagerClient(
          { get_access_token: async () => undefined },
          SETTINGS,
          new ManagedSettingsClient(),
        );

        const error = await rejection(client.user_crypto_management().user_key_id_needs_backfill());

        expect(error.variant).toBe("StateBridgeNotRegistered");
      },
      TIMEOUT,
    );
  });

  describe("user_key_id_backfill", () => {
    it(
      "posts the current user key id and stores it as the server's",
      async () => {
        mock = installHttpMock({ [ROUTE]: () => ({}) });
        const client = await makeV2AccountClient(bridge, SETTINGS);

        await client.user_crypto_management().user_key_id_backfill();

        expect(mock.routes()).toEqual([ROUTE]);
        const posted = mock.bodyFor(ROUTE);
        expect(Object.keys(posted)).toEqual(["userKeyId"]);
        expect(posted.userKeyId).toMatch(KEY_ID_PATTERN);

        // The id crossed the FFI boundary in both directions and came back unchanged.
        expect(await bridge.get_user_key_id()).toEqual(posted.userKeyId);
        // Nothing left to backfill.
        expect(await client.user_crypto_management().user_key_id_needs_backfill()).toBe(false);
      },
      TIMEOUT,
    );

    it(
      "leaves stored state untouched when the server rejects the key id",
      async () => {
        mock = installHttpMock({ [ROUTE]: () => ({ status: 400, json: { message: "nope" } }) });
        const client = await makeV2AccountClient(bridge, SETTINGS);

        const error = await rejection(client.user_crypto_management().user_key_id_backfill());

        expect(error.variant).toBe("Api");
        expect(await bridge.get_user_key_id()).toBeFalsy();
        // Still outstanding, so a later attempt can retry.
        expect(await client.user_crypto_management().user_key_id_needs_backfill()).toBe(true);
      },
      TIMEOUT,
    );

    it(
      "backfills a V1 account the same way, using the id its user key derives",
      async () => {
        mock = installHttpMock({ [ROUTE]: () => ({}) });
        const client = await makeInitializedPasswordmanagerClient(bridge, SETTINGS);

        await client.user_crypto_management().user_key_id_backfill();

        expect(mock.routes()).toEqual([ROUTE]);
        const posted = mock.bodyFor(ROUTE);
        expect(posted.userKeyId).toMatch(KEY_ID_PATTERN);

        expect(await bridge.get_user_key_id()).toEqual(posted.userKeyId);
        expect(await client.user_crypto_management().user_key_id_needs_backfill()).toBe(false);
      },
      TIMEOUT,
    );
  });
});
