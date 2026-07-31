import { PasswordManagerClient, init_sdk } from "@bitwarden/sdk-internal";

import { makeStateBridge, makeV2AccountClient } from "../utils";
import { CHANGED_KDF_PARAMS, SYNC_VECTOR } from "./crypto-sync-fixtures";

describe("crypto sync handler", () => {
  describe("state", () => {
    it("applies a full sync payload to state", async () => {
      const bridge = makeStateBridge();
      const client = await makeV2AccountClient(bridge);

      await client.crypto_sync_handler().on_sync(SYNC_VECTOR);

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
    });

    it("clears a stored upgrade token when the server reports none", async () => {
      const bridge = makeStateBridge();
      const client = await makeV2AccountClient(bridge);
      await client.crypto_sync_handler().on_sync(SYNC_VECTOR);
      expect(await bridge.get_v2_upgrade_token()).toBeTruthy();

      // An absent token means the V1 to V2 upgrade is no longer outstanding.
      const { v2UpgradeToken: _dropped, ...userDecryption } = SYNC_VECTOR.userDecryption!;
      await client.crypto_sync_handler().on_sync({ ...SYNC_VECTOR, userDecryption });

      expect(await bridge.get_v2_upgrade_token()).toBeFalsy();
    });

    it("clears stored master password unlock data when the server reports none", async () => {
      const bridge = makeStateBridge();
      const client = await makeV2AccountClient(bridge);
      await client.crypto_sync_handler().on_sync(SYNC_VECTOR);
      expect(await bridge.get_masterpassword_unlock_data()).toBeTruthy();

      // An absent unlock method means the account no longer has a master password.
      const { masterPasswordUnlock: _dropped, ...userDecryption } = SYNC_VECTOR.userDecryption!;
      await client.crypto_sync_handler().on_sync({ ...SYNC_VECTOR, userDecryption });

      expect(await bridge.get_masterpassword_unlock_data()).toBeFalsy();
    });

    it("keeps the stored kdf settings when the server reports no master password", async () => {
      const bridge = makeStateBridge();
      const client = await makeV2AccountClient(bridge);
      await client.crypto_sync_handler().on_sync(SYNC_VECTOR);

      // The kdf only reaches the client as part of the master password unlock data, but an account
      // without a master password still has kdf settings — PIN unlock derives from them.
      const { masterPasswordUnlock: _dropped, ...userDecryption } = SYNC_VECTOR.userDecryption!;
      await client.crypto_sync_handler().on_sync({ ...SYNC_VECTOR, userDecryption });

      expect(await bridge.get_kdf()).toEqual(SYNC_VECTOR.userDecryption!.masterPasswordUnlock!.kdf);
    });

    it("updates the stored kdf settings when the server reports new ones", async () => {
      const bridge = makeStateBridge();
      const client = await makeV2AccountClient(bridge);
      await client.crypto_sync_handler().on_sync(SYNC_VECTOR);

      const masterPasswordUnlock = {
        ...SYNC_VECTOR.userDecryption!.masterPasswordUnlock!,
        kdf: CHANGED_KDF_PARAMS,
      };
      await client.crypto_sync_handler().on_sync({
        ...SYNC_VECTOR,
        userDecryption: { ...SYNC_VECTOR.userDecryption!, masterPasswordUnlock },
      });

      expect(await bridge.get_kdf()).toEqual(CHANGED_KDF_PARAMS);
    });

    it("does not throw when no state bridge is registered", async () => {
      // Built without `makePasswordManagerClient`, which always registers a bridge. The handler has
      // to no-op rather than fail when a host has not wired one up.
      init_sdk();
      const client = new PasswordManagerClient({ get_access_token: async () => undefined });

      await expect(client.crypto_sync_handler().on_sync(SYNC_VECTOR)).resolves.toBeUndefined();
    });
  });
});
