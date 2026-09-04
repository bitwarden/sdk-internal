// What a client persists: the state bridge and the client-managed repositories, together.
//
// The bridge on a `LocalState` is always fresh. That matters: a bridge still holding the previous
// user key lets an unlock "succeed" by reading the key back rather than deriving it, so a test that
// reuses one can pass against a client that has stopped being able to unlock at all.

import type {
  Cipher,
  ClientSettings,
  Folder,
  InitUserCryptoMethod,
  Kdf,
  MasterPasswordUnlockData,
  PasswordManagerClient,
  Repository,
  V2UpgradeToken,
  WrappedAccountCryptographicState,
} from "@bitwarden/sdk-internal";

import { asOrganizationId, asUnsignedSharedKey, asUserId } from "../type-assertion-helpers";
import { makePasswordManagerClient, makeStateBridge } from "../utils";

import { API_URL, IDENTITY_URL } from "./urls";

/** Points the SDK at the model server. Nothing listens; every request is served by the fetch mock. */
export const SETTINGS: ClientSettings = { apiUrl: API_URL, identityUrl: IDENTITY_URL };

/** A `Repository` backed by a `Map`, with a dump for assertions. */
export class TestRepository<T extends { id?: unknown }> implements Repository<T> {
  private readonly items = new Map<string, T>();

  async get(id: string): Promise<T | null> {
    return this.items.get(id) ?? null;
  }

  async list(): Promise<T[]> {
    return [...this.items.values()];
  }

  async set(id: string, value: T): Promise<void> {
    this.items.set(id, value);
  }

  async setBulk(values: [string, T][]): Promise<void> {
    for (const [id, value] of values) {
      this.items.set(id, value);
    }
  }

  async remove(id: string): Promise<void> {
    this.items.delete(id);
  }

  async removeBulk(keys: string[]): Promise<void> {
    for (const key of keys) {
      this.items.delete(key);
    }
  }

  async removeAll(): Promise<void> {
    this.items.clear();
  }

  /** Synchronous read of everything held, for assertions. */
  dump(): T[] {
    return [...this.items.values()];
  }
}

/** The account identity and key material a client needs to bring itself up. */
export interface LocalAccount {
  userId: string;
  email: string;
  accountCryptographicState: WrappedAccountCryptographicState;
  kdf: Kdf;
  masterPasswordUnlock?: MasterPasswordUnlockData;
  upgradeToken?: V2UpgradeToken;
  /** Organization keys sealed to this account, keyed by organization id. */
  organizationKeys?: Record<string, string>;
}

export class LocalState {
  readonly bridge = makeStateBridge();
  readonly ciphers = new TestRepository<Cipher>();
  readonly folders = new TestRepository<Folder>();

  private account: LocalAccount | undefined;

  /** The account this state belongs to. Throws before it has been seeded. */
  get seededAccount(): LocalAccount {
    if (this.account === undefined) {
      throw new Error("local state has no account; call seedAccount first");
    }
    return this.account;
  }

  async seedAccount(account: LocalAccount): Promise<void> {
    this.account = account;
    await this.bridge.set_account_cryptographic_state(account.accountCryptographicState);
    await this.bridge.set_kdf_config(account.kdf);

    if (account.masterPasswordUnlock !== undefined) {
      await this.bridge.set_masterpassword_unlock_data(account.masterPasswordUnlock);
    }
    if (account.upgradeToken !== undefined) {
      await this.bridge.set_v2_upgrade_token(account.upgradeToken);
    }
  }

  /** Replaces the repositories' contents. An omitted collection is left alone. */
  async seedVault(vault: { ciphers?: Cipher[]; folders?: Folder[] }): Promise<void> {
    if (vault.ciphers !== undefined) {
      await this.ciphers.removeAll();
      await this.ciphers.setBulk(vault.ciphers.map((cipher) => [String(cipher.id), cipher]));
    }
    if (vault.folders !== undefined) {
      await this.folders.removeAll();
      await this.folders.setBulk(vault.folders.map((folder) => [String(folder.id), folder]));
    }
  }

  /**
   * Drops the state a running process holds but a restarted one would not.
   *
   * This is what separates "the app is locked" from "the app was closed", and therefore what
   * separates a PIN unlock before the first unlock from one after it.
   */
  async clearEphemeral(): Promise<void> {
    await this.bridge.clear_user_key();
    await this.bridge.clear_ephemeral_pin_envelope();
  }

  /** Brings a client up on this state and unlocks it with `method`. */
  async unlock(method: InitUserCryptoMethod): Promise<PasswordManagerClient> {
    const account = this.seededAccount;
    const client = makePasswordManagerClient(this.bridge, SETTINGS);

    client.platform().state().register_client_managed_repositories({
      cipher: this.ciphers,
      folder: this.folders,
      local_user_data_key_state: null,
      organization_shared_key: null,
      send: null,
    });

    await client.crypto().initialize_user_crypto({
      userId: asUserId(account.userId),
      email: account.email,
      kdfParams: account.kdf,
      accountCryptographicState: account.accountCryptographicState,
      method,
      ...(account.upgradeToken === undefined ? {} : { upgradeToken: account.upgradeToken }),
    });

    const organizationKeys = Object.entries(account.organizationKeys ?? {});
    if (organizationKeys.length > 0) {
      await client.crypto().initialize_org_crypto({
        organizationKeys: new Map(
          organizationKeys.map(([id, key]) => [asOrganizationId(id), asUnsignedSharedKey(key)]),
        ),
      });
    }

    return client;
  }
}
