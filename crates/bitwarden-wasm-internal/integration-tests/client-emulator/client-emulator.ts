// The client side of a test: the state a real client persists, plus the two operations that move an
// account into it — a sync from the server, and an unlock.

import type {
  InitUserCryptoMethod,
  LoginRequest,
  PasswordManagerClient,
  WasmStateBridge,
} from "@bitwarden/sdk-internal";

import { AccountKeysResponse, toKdf, type SyncResponse } from "../server-emulator/dto";
import type { ServerEmulator } from "../server-emulator/server-emulator";
import { API_URL } from "../server-emulator/urls";
import { asEncString, asKeyId } from "../tests/type-assertion-helpers";

import { LocalState, SETTINGS } from "./local-state";

import { makePasswordManagerClient, makeStateBridge } from "../tests/utils";

/** How a client gets to the point where it may sync an account down. */
export enum LoginMethod {
  /** Prelogin, then the password grant — what a real password client does. */
  Password = "password",

  /** Skips authentication entirely, for accounts for that real login is not implemented. Note this only works when using the emulator */
  ForceLogin = "force-login",
}

/** The device a test logs in from. Identity records it; nothing here depends on the values. */
const LOGIN_REQUEST: LoginRequest = {
  clientId: "web",
  device: {
    deviceType: "SDK",
    deviceIdentifier: "integration-test-device",
    deviceName: "Integration Tests",
    devicePushToken: undefined,
  },
};

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

    const response = await fetch(`${API_URL}/sync`, {
      headers: { Authorization: `Bearer ${user.userId}` },
    });
    if (!response.ok) {
      throw new Error(`sync for ${email} answered ${response.status}`);
    }

    const synced: SyncResponse = await response.json();
    const unlock = synced.userDecryption.masterPasswordUnlock;
    const { v2UpgradeToken, userKeyId } = synced.userDecryption;

    const accountKeys = AccountKeysResponse.fromAccountKeysResponse(synced.profile.accountKeys);

    const locked = makePasswordManagerClient(this.local.bridge, SETTINGS, user.userId);
    await locked.crypto_sync_handler().on_sync({
      accountCryptographicState: accountKeys.toAccountCryptographicState(),
      userDecryption: {
        masterPasswordUnlock:
          unlock === undefined
            ? undefined
            : {
                masterKeyWrappedUserKey: asEncString(unlock.masterKeyEncryptedUserKey),
                salt: unlock.salt,
                kdf: toKdf(unlock.kdf),
                containedKeyId:
                  unlock.containedKeyId === undefined ? undefined : asKeyId(unlock.containedKeyId),
              },
        v2UpgradeToken:
          v2UpgradeToken === undefined
            ? undefined
            : {
                wrapped_user_key_1: asEncString(v2UpgradeToken.wrappedUserKey1),
                wrapped_user_key_2: asEncString(v2UpgradeToken.wrappedUserKey2),
              },
        userKeyId: userKeyId === undefined ? undefined : asKeyId(userKeyId),
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

  /**
   * Logs an account in and syncs it down. Leaves the client locked.
   *
   * {@link LoginMethod.Password} authenticates against the identity emulator first and so needs
   * the account's password; {@link LoginMethod.ForceLogin} goes straight to the sync.
   */
  async login(email: string, method: LoginMethod, password?: string): Promise<void> {
    if (method === LoginMethod.Password) {
      if (password === undefined) {
        throw new Error(`a password login for ${email} needs a password`);
      }

      await this.authenticate(email, password);
    }

    await this.sync(email);
  }

  /**
   * Prelogin, then the password grant.
   *
   * The login client is unauthenticated and carries no account, so it runs on a bridge of its own
   * rather than this client's state.
   */
  private async authenticate(email: string, password: string): Promise<void> {
    const login = makePasswordManagerClient(makeStateBridge(), SETTINGS).auth().login();

    const preloginResponse = await login.get_password_prelogin(email);
    await login.login_via_password({
      loginRequest: LOGIN_REQUEST,
      email,
      password,
      preloginResponse,
    });
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

  /**
   * Re-initializes an unlocked client after the cryptographic keys changed after a sync.
   */
  async reinit(): Promise<void> {
    const accountCryptographicState = await this.local.bridge.get_account_cryptographic_state();
    const upgradeToken = await this.local.bridge.get_v2_upgrade_token();
    if (accountCryptographicState === null || upgradeToken === null) {
      throw new Error("local state holds no upgraded key material; sync one down first");
    }

    await this.getPasswordManagerClient()
      .crypto()
      .reinit_user_crypto({ accountCryptographicState, upgradeToken });
  }

  /** Drops the state a running process holds but a restarted one would not: a lock, not a logout. */
  async lock(): Promise<void> {
    await this.local.clearEphemeral();

    // The client is part of that state: an unlocked one kept across a lock would still decrypt, so
    // it is replaced by a fresh locked one, as restarting the app would.
    this.client = this.local.locked();
  }
}
