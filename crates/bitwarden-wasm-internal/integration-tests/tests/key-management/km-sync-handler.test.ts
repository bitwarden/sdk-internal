import {
  ClientSettings,
  KmSyncData,
  PasswordManagerClient,
  init_sdk,
} from "@bitwarden/sdk-internal";

import { HttpMock, installHttpMock } from "../http-mock";
import {
  makeInitializedPasswordmanagerClient,
  makePasswordManagerClient,
  makeStateBridge,
  makeV2AccountClient,
} from "../utils";
import { V2_USER_KEY_ID } from "../v2-fixtures";
import {
  CHANGED_KDF_PARAMS,
  ROUTES,
  SYNC_VECTOR,
  kmSyncRoutes,
  withoutUserKeyId,
} from "./km-sync-fixtures";

// Nothing listens here; every request is served by the fetch mock. A concrete host keeps the SDK's
// request URLs parseable and makes an unmocked route fail loudly rather than escape to the network.
const SETTINGS: ClientSettings = {
  apiUrl: "http://localhost:4000",
  identityUrl: "http://localhost:4000/identity",
};

describe("km sync handler", () => {
  let mock: HttpMock;

  beforeEach(() => {
    mock = installHttpMock(kmSyncRoutes());
  });

  afterEach(() => {
    expect(mock.unmatched.map((r) => r.route)).toEqual([]);
    mock.restore();
  });

  describe("state", () => {
    it("applies a full sync payload to state", async () => {
      const bridge = makeStateBridge();
      const client = await makeV2AccountClient(bridge, SETTINGS);

      await client.km_sync_handler().on_sync(SYNC_VECTOR);

      expect(await bridge.get_masterpassword_unlock_data()).toEqual(
        SYNC_VECTOR.userDecryption!.masterPasswordUnlock,
      );
      expect(await bridge.get_v2_upgrade_token()).toEqual(
        SYNC_VECTOR.userDecryption!.v2UpgradeToken,
      );
      expect(await bridge.get_account_cryptographic_state()).toEqual(
        SYNC_VECTOR.accountCryptographicState,
      );
      expect(await bridge.get_kdf()).toEqual(SYNC_VECTOR.userDecryption!.masterPasswordUnlock!.kdf);
      // The server already knows the key id, so there is nothing to report.
      expect(mock.routes()).toEqual([]);
    });

    it("clears a stored upgrade token when the server reports none", async () => {
      const bridge = makeStateBridge();
      const client = await makeV2AccountClient(bridge, SETTINGS);
      await client.km_sync_handler().on_sync(SYNC_VECTOR);
      expect(await bridge.get_v2_upgrade_token()).toBeTruthy();

      // An absent token means the V1 to V2 upgrade is no longer outstanding.
      const { v2UpgradeToken: _dropped, ...userDecryption } = SYNC_VECTOR.userDecryption!;
      await client.km_sync_handler().on_sync({ ...SYNC_VECTOR, userDecryption });

      expect(await bridge.get_v2_upgrade_token()).toBeFalsy();
    });

    it("clears stored master password unlock data when the server reports none", async () => {
      const bridge = makeStateBridge();
      const client = await makeV2AccountClient(bridge, SETTINGS);
      await client.km_sync_handler().on_sync(SYNC_VECTOR);
      expect(await bridge.get_masterpassword_unlock_data()).toBeTruthy();

      // An absent unlock method means the account no longer has a master password.
      const { masterPasswordUnlock: _dropped, ...userDecryption } = SYNC_VECTOR.userDecryption!;
      await client.km_sync_handler().on_sync({ ...SYNC_VECTOR, userDecryption });

      expect(await bridge.get_masterpassword_unlock_data()).toBeFalsy();
    });

    it("keeps the stored kdf settings when the server reports no master password", async () => {
      const bridge = makeStateBridge();
      const client = await makeV2AccountClient(bridge, SETTINGS);
      await client.km_sync_handler().on_sync(SYNC_VECTOR);

      // The kdf only reaches the client as part of the master password unlock data, but an account
      // without a master password still has kdf settings — PIN unlock derives from them.
      const { masterPasswordUnlock: _dropped, ...userDecryption } = SYNC_VECTOR.userDecryption!;
      await client.km_sync_handler().on_sync({ ...SYNC_VECTOR, userDecryption });

      expect(await bridge.get_kdf()).toEqual(SYNC_VECTOR.userDecryption!.masterPasswordUnlock!.kdf);
    });

    it("updates the stored kdf settings when the server reports new ones", async () => {
      const bridge = makeStateBridge();
      const client = await makeV2AccountClient(bridge, SETTINGS);
      await client.km_sync_handler().on_sync(SYNC_VECTOR);

      const masterPasswordUnlock = {
        ...SYNC_VECTOR.userDecryption!.masterPasswordUnlock!,
        kdf: CHANGED_KDF_PARAMS,
      };
      await client.km_sync_handler().on_sync({
        ...SYNC_VECTOR,
        userDecryption: { ...SYNC_VECTOR.userDecryption!, masterPasswordUnlock },
      });

      expect(await bridge.get_kdf()).toEqual(CHANGED_KDF_PARAMS);
    });

    it("does not throw when no state bridge is registered", async () => {
      // Built without `makePasswordManagerClient`, which always registers a bridge. The handler has
      // to no-op rather than fail when a host has not wired one up.
      init_sdk();
      const client = new PasswordManagerClient(
        { get_access_token: async () => undefined },
        SETTINGS,
      );

      await expect(client.km_sync_handler().on_sync(SYNC_VECTOR)).resolves.toBeUndefined();
    });
  });

  describe("user key id backfill", () => {
    it("reports the user key id when the server has none", async () => {
      const bridge = makeStateBridge();
      const client = await makeV2AccountClient(bridge, SETTINGS);

      await client.km_sync_handler().on_sync(withoutUserKeyId());

      expect(mock.bodyFor(ROUTES.postUserKeyId)).toEqual({ userKeyId: V2_USER_KEY_ID });
    });

    it("does not report anything for a locked client", async () => {
      // No `initialize_user_crypto`, so there is no user key to take an id from.
      const client = makePasswordManagerClient(makeStateBridge(), SETTINGS);

      await client.km_sync_handler().on_sync(withoutUserKeyId());

      expect(mock.called(ROUTES.postUserKeyId)).toBe(false);
    });

    it("does not report anything for a V1 account", async () => {
      // A V1 user key is Aes256CbcHmac, an algorithm that carries no key id. Support will be added later.
      const client = await makeInitializedPasswordmanagerClient(makeStateBridge());

      await client.km_sync_handler().on_sync(withoutUserKeyId());

      expect(mock.called(ROUTES.postUserKeyId)).toBe(false);
    });
  });
});
