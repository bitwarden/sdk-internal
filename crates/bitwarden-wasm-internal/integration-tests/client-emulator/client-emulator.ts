// The client side of a test: the state a real client persists, plus the two operations that move an
// account into it — a sync from the server, and an unlock.

import type {
  InitUserCryptoMethod,
  PasswordManagerClient,
  WasmStateBridge,
} from "@bitwarden/sdk-internal";

import { AccountKeysResponse, toKdf, type SyncResponse } from "../server-emulator/dto";
import type { ServerEmulator } from "../server-emulator/server-emulator";
import { API_URL } from "../server-emulator/urls";
import { asEncString, asKeyId } from "../tests/type-assertion-helpers";

import { LocalState, SETTINGS } from "./local-state";

import { makePasswordManagerClient } from "../tests/utils";

export class ClientEmulator {
  readonly local = new LocalState();

  private client: PasswordManagerClient | undefined;

  constructor(private readonly server: ServerEmulator) {}

  /** The state bridge this client persists to. */
  get bridge(): WasmStateBridge {
    return this.local.bridge;
  }

  /**
   * Simulates a sync from server to client.
   */
  async sync(email: string): Promise<void> {
    const user = this.server.getUser(email);

    this.local.setIdentity({ userId: user.userId, email: user.email });
    this.local.organizationKeys = user.organizationKeys;

    const response = await fetch(`${API_URL}/sync`, {
      headers: { Authorization: `Bearer ${user.userId}` },
    });
    if (!response.ok) {
      throw new Error(`sync for ${email} answered ${response.status}`);
    }

    const synced: SyncResponse = await response.json();
    const unlock = synced.userDecryption.masterPasswordUnlock;

    const accountKeys = AccountKeysResponse.fromAccountKeysResponse(synced.profile.accountKeys);

    const locked = makePasswordManagerClient(this.local.bridge, SETTINGS, user.userId);
    await locked.crypto_sync_handler().on_sync({
      accountCryptographicState: accountKeys.toAccountCryptographicState(),
      userDecryption: {
        ...(unlock === undefined
          ? {}
          : {
              masterPasswordUnlock: {
                masterKeyWrappedUserKey: asEncString(unlock.masterKeyEncryptedUserKey),
                salt: unlock.salt,
                kdf: toKdf(unlock.kdf),
              },
            }),
        ...(synced.userDecryption.v2UpgradeToken === undefined
          ? {}
          : {
              v2UpgradeToken: {
                wrapped_user_key_1: asEncString(
                  synced.userDecryption.v2UpgradeToken.wrappedUserKey1,
                ),
                wrapped_user_key_2: asEncString(
                  synced.userDecryption.v2UpgradeToken.wrappedUserKey2,
                ),
              },
            }),
        ...(synced.userDecryption.userKeyId === undefined
          ? {}
          : { userKeyId: asKeyId(synced.userDecryption.userKeyId) }),
      },
    });

    // Quirk, the crypto sync handler writes the kdf only when the account has no master-password
    // but clients always write it. The KDF a real client learns at `POST /accounts/prelogin`.
    if (unlock === undefined) {
      await this.local.bridge.set_kdf_config(user.kdf);
    }

    // The vault the server would serve this account, not the whole database: an account's local
    // state must not hold items a sync could never hand it.
    await this.local.seedVault(this.server.api.vaultFor(user));
  }

  /** Syncs a seeded account down — what a login does. Leaves the client locked. */
  async login(email: string): Promise<void> {
    await this.sync(email);
  }

  /**
   * Unlocks with the master password, against the unlock data the sync left behind.
   *
   * The password is the caller's to supply — it is the one thing neither emulator holds.
   */
  async unlock(password: string): Promise<void> {
    const unlockData = await this.local.bridge.get_masterpassword_unlock_data();
    if (unlockData === null) {
      throw new Error("local state holds no master-password unlock data; sync one down first");
    }

    this.client = await this.local.unlock({
      masterPasswordUnlock: { password, master_password_unlock: unlockData },
    });
  }

  /** Brings a client up with an unlock method the test supplies rather than the account's own. */
  async unlockWith(method: InitUserCryptoMethod): Promise<void> {
    this.client = await this.local.unlock(method);
  }

  /** The unlocked client. Throws before an unlock, since there is nothing to drive yet. */
  getPasswordManagerClient(): PasswordManagerClient {
    if (this.client === undefined) {
      throw new Error("no client; unlock first");
    }

    return this.client;
  }

  /** Unlocks from a user key the client already holds, as a keyless login leaves it. */
  async unlockWithUserKey(userKey: string): Promise<void> {
    this.client = await this.local.unlock({ decryptedKey: { decrypted_user_key: userKey } });
  }

  /** Drops the state a running process holds but a restarted one would not: a lock, not a logout. */
  async lock(): Promise<void> {
    await this.local.clearEphemeral();

    // The client is part of that state: an unlocked one kept across a lock would still decrypt, so
    // it is replaced by a fresh locked one, as restarting the app would.
    this.client = this.local.locked();
  }
}
