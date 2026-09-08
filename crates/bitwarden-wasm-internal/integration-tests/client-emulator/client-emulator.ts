// The client side of a test: the state a real client persists, plus the two operations that move an
// account into it — a sync from the server, and an unlock.

import type {
  CryptoSyncData,
  InitUserCryptoMethod,
  PasswordManagerClient,
  WasmStateBridge,
} from "@bitwarden/sdk-internal";

import type { ServerEmulator } from "../server-emulator/server-emulator";

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
   * Simulates a sync from server to client
   */
  async sync(email: string): Promise<void> {
    const user = this.server.getUser(email);

    this.local.setIdentity({ userId: user.userId, email: user.email });
    this.local.organizationKeys = user.organizationKeys;

    const data: CryptoSyncData = {
      accountCryptographicState: user.accountCryptographicState,
      userDecryption: {
        ...(user.masterPasswordUnlock === null
          ? {}
          : {
              masterPasswordUnlock: {
                masterKeyWrappedUserKey: user.masterPasswordUnlock.masterKeyWrappedUserKey,
                salt: user.masterPasswordUnlock.salt,
                kdf: user.masterPasswordUnlock.kdf,
              },
            }),
        ...(user.upgradeToken === undefined ? {} : { v2UpgradeToken: user.upgradeToken }),
        ...(user.userKeyId === undefined ? {} : { userKeyId: user.userKeyId }),
      },
    };

    const locked = makePasswordManagerClient(this.local.bridge, SETTINGS, user.userId);
    await locked.crypto_sync_handler().on_sync(data);

    await this.local.bridge.set_kdf_config(user.masterPasswordUnlock?.kdf ?? user.kdf);

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
  }
}
