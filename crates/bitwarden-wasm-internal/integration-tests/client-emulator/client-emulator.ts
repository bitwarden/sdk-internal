// The client side of a test: the state a real client persists, plus the two operations that move an
// account into it — a sync from the server, and an unlock.

import type {
  ClientSettings,
  InitUserCryptoMethod,
  Kdf,
  LoginClient,
  LoginRequest,
  PasswordManagerClient,
  WasmStateBridge,
} from "@bitwarden/sdk-internal";

import {
  AccountKeysResponse,
  CipherResponse,
  FolderResponse,
  toKdf,
  type SyncResponse,
} from "../server-emulator/dto";
import type { ServerEmulator } from "../server-emulator/server-emulator";
import { asEncString, asKeyId } from "../tests/type-assertion-helpers";

import { LocalState } from "./local-state";

import { makePasswordManagerClient, makeStateBridge } from "../tests/utils";

/** How a client gets to the point where it may sync an account down. */
export enum LoginMethod {
  /** Prelogin, then the password grant — what a real password client does. */
  Password = "password",

  /** Skips authentication entirely, for accounts for that real login is not implemented. Note this only works when using the emulator */
  ForceLogin = "force-login",
}

/** The device a test logs in from. Identity records it; nothing here depends on the values. */
export const LOGIN_REQUEST: LoginRequest = {
  clientId: "web",
  device: {
    deviceType: "SDK",
    deviceIdentifier: "integration-test-device",
    deviceName: "Integration Tests",
    devicePushToken: undefined,
  },
};

export class ClientEmulator {
  readonly local: LocalState;

  private client: PasswordManagerClient | undefined;

  private preloginKdf: Kdf | undefined;

  /**
   * @param settings where the SDK points, which is also where this client's own requests go.
   * @param server the emulator, when there is one. Only {@link LoginMethod.ForceLogin} needs it.
   */
  constructor(
    private readonly settings: ClientSettings,
    private readonly server?: ServerEmulator,
    private readonly loginRequest: LoginRequest = LOGIN_REQUEST,
  ) {
    this.local = new LocalState(settings);
  }

  /** The state bridge this client persists to. */
  get bridge(): WasmStateBridge {
    return this.local.bridge;
  }

  /**
   * Simulates a sync from server to client.
   *
   * Everything comes off the response: the account this client belongs to is whichever one its
   * token authenticates, not something the caller names.
   */
  async sync(): Promise<void> {
    const response = await fetch(`${this.settings.apiUrl}/sync?excludeDomains=true`, {
      headers: { Authorization: `Bearer ${this.local.token}` },
    });
    if (!response.ok) {
      throw new Error(`sync answered ${response.status}: ${await response.text()}`);
    }

    const synced: SyncResponse = await response.json();

    this.local.setIdentity({ userId: synced.profile.id, email: synced.profile.email });
    this.local.organizationKeys = Object.fromEntries(
      synced.profile.organizations.map((organization) => [organization.id, organization.key]),
    );

    const unlock = synced.userDecryption.masterPasswordUnlock;
    const { v2UpgradeToken, userKeyId } = synced.userDecryption;

    const accountKeys = AccountKeysResponse.fromAccountKeysResponse(synced.profile.accountKeys);

    const locked = makePasswordManagerClient(this.local.bridge, this.settings, this.local.token);
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
      if (this.preloginKdf === undefined) {
        throw new Error(
          "the synced account has no master-password unlock data and no prelogin KDF",
        );
      }

      await this.local.bridge.set_kdf_config(this.preloginKdf);
    }

    await this.local.seedVault({
      ciphers: await Promise.all(
        synced.ciphers.map(async (cipher) =>
          CipherResponse.toCipher(cipher, (await this.local.ciphers.get(cipher.id)) ?? undefined),
        ),
      ),
      folders: synced.folders.map(FolderResponse.toFolder),
    });
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
    } else {
      if (this.server === undefined) {
        throw new Error(`${method} needs the server emulator; a real server cannot mint a token`);
      }

      // Prelogin still runs: it is unauthenticated, so a client with no master password reaches it
      // too, and it is the only place an account learns its KDF.
      this.preloginKdf = (await this.loginClient().get_password_prelogin(email)).kdf;
      this.local.setAccessToken(this.server.identity.issueToken(email));
    }

    await this.sync();
  }

  /**
   * Prelogin, then the password grant.
   *
   * The login client is unauthenticated and carries no account, so it runs on a bridge of its own
   * rather than this client's state.
   */
  private async authenticate(email: string, password: string): Promise<void> {
    const login = this.loginClient();

    const preloginResponse = await login.get_password_prelogin(email);
    const response = await login.login_via_password({
      loginRequest: this.loginRequest,
      email,
      password,
      preloginResponse,
    });

    this.preloginKdf = preloginResponse.kdf;
    this.local.setAccessToken(response.Authenticated.accessToken);
  }

  /** An unauthenticated login client, which carries no account and so runs on a bridge of its own. */
  private loginClient(): LoginClient {
    return makePasswordManagerClient(makeStateBridge(), this.settings).auth().login();
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
