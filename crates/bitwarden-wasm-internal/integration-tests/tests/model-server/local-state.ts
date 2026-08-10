// A client's local state, named.
//
// Local state is really three things — the in-memory state bridge, the cipher repository and the folder
// repository — and before this they were three separate things constructed inline at every call site.
// Naming the group gives tests a handle on all of it, and gives the two helpers in `sync.ts` something
// concrete to write into.
//
// The bridge is always fresh. A bridge carrying a previous generation's user key could let an unlock
// succeed by reading the key back instead of deriving it from the master password, which would hollow
// out every test that rebuilds a client to prove the last write is still usable.

import type {
  Cipher,
  ClientSettings,
  Folder,
  InitUserCryptoMethod,
  PasswordManagerClient,
  Repository,
  WasmStateBridge,
} from "@bitwarden/sdk-internal";

import { makePasswordManagerClient, makeStateBridge } from "../utils";

import { API_URL } from "./urls";

export const SETTINGS: ClientSettings = {
  apiUrl: API_URL,
  identityUrl: `${API_URL}/identity`,
};

/** An in-memory `Repository<T>`, with a `dump` for assertions. */
export class TestRepository<T> implements Repository<T> {
  private readonly store: Map<string, T>;

  constructor(seed: T[] = []) {
    this.store = new Map(seed.map((item) => [String((item as { id: unknown }).id), item]));
  }

  async get(id: string): Promise<T | null> {
    return this.store.get(id) ?? null;
  }

  async list(): Promise<T[]> {
    return [...this.store.values()];
  }

  async set(id: string, value: T): Promise<void> {
    this.store.set(id, value);
  }

  async setBulk(values: [string, T][]): Promise<void> {
    for (const [id, value] of values) this.store.set(id, value);
  }

  async remove(id: string): Promise<void> {
    this.store.delete(id);
  }

  async removeBulk(keys: string[]): Promise<void> {
    for (const key of keys) this.store.delete(key);
  }

  async removeAll(): Promise<void> {
    this.store.clear();
  }

  dump(): T[] {
    return [...this.store.values()];
  }
}

/** The account material a client needs before it can unlock. */
export interface LocalAccount {
  userId: string;
  email: string;
  /** `WrappedAccountCryptographicState`, in the SDK's shape. */
  accountCryptographicState: unknown;
  kdf: unknown;
  masterPasswordUnlock?: {
    masterKeyWrappedUserKey: string;
    salt: string;
    kdf: unknown;
  } | null;
  upgradeToken?: unknown;
  /** Organization keys sealed to this account, keyed by organization id. */
  organizationKeys?: Record<string, unknown>;
}

export class LocalState {
  readonly bridge: WasmStateBridge = makeStateBridge();
  readonly ciphers = new TestRepository<Cipher>();
  readonly folders = new TestRepository<Folder>();

  private account: LocalAccount | undefined;

  /** Writes the account's keys into the bridge, replacing whatever was there. */
  async seedAccount(account: LocalAccount): Promise<void> {
    this.account = account;
    await this.bridge.set_account_cryptographic_state(account.accountCryptographicState as never);
    await this.bridge.set_kdf_config(account.kdf as never);
    if (account.masterPasswordUnlock != null) {
      await this.bridge.set_masterpassword_unlock_data({
        kdf: account.masterPasswordUnlock.kdf,
        masterKeyWrappedUserKey: account.masterPasswordUnlock.masterKeyWrappedUserKey,
        salt: account.masterPasswordUnlock.salt,
      } as never);
    }
  }

  /** Replaces the vault in the repositories. Omitted collections are left untouched. */
  async seedVault(items: { ciphers?: Cipher[]; folders?: Folder[] }): Promise<void> {
    if (items.ciphers !== undefined) {
      await this.ciphers.removeAll();
      await this.ciphers.setBulk(items.ciphers.map((c) => [String(c.id), c] as [string, Cipher]));
    }
    if (items.folders !== undefined) {
      await this.folders.removeAll();
      await this.folders.setBulk(items.folders.map((f) => [String(f.id), f] as [string, Folder]));
    }
  }

  /**
   * Drops the state that only lives for the lifetime of a process, so the next unlock has to stand on
   * what was actually persisted.
   *
   * This is what an app loses when it is fully closed, as opposed to merely locked, and it is what makes
   * the two PIN lock types distinguishable: `BeforeFirstUnlock` writes a persistent envelope that
   * survives this, `AfterFirstUnlock` writes only an ephemeral one that does not. Without it, a PIN
   * enrolled either way still opens the vault and the distinction is invisible.
   */
  async clearEphemeral(): Promise<void> {
    await this.bridge.clear_user_key();
    await this.bridge.clear_ephemeral_pin_envelope();
  }

  /**
   * Builds a client on this local state and unlocks it.
   */
  async unlock(method: InitUserCryptoMethod): Promise<PasswordManagerClient> {
    const account = this.account;
    if (account === undefined) {
      throw new Error("local state has no account; seed it or sync a server down first");
    }

    const client = makePasswordManagerClient(this.bridge, SETTINGS);
    client
      .platform()
      .state()
      .register_client_managed_repositories({
        cipher: this.ciphers,
        folder: this.folders,
        user_key_state: null,
        local_user_data_key_state: null,
        ephemeral_pin_envelope_state: null,
        organization_shared_key: null,
        send: null,
      } as never);

    await client.crypto().initialize_user_crypto({
      userId: account.userId as never,
      kdfParams: (await this.bridge.get_kdf_config()) ?? (account.kdf as never),
      email: account.email,
      accountCryptographicState: (await this.bridge.get_account_cryptographic_state()) as never,
      method,
      upgradeToken: account.upgradeToken as never,
    });

    // Organization keys, in the order a real client uses them: the user key must be available before
    // `initialize_org_crypto` can unseal them.
    const organizationKeys = account.organizationKeys ?? {};
    if (Object.keys(organizationKeys).length > 0) {
      await client.crypto().initialize_org_crypto({
        organizationKeys: new Map(Object.entries(organizationKeys)) as never,
      });
    }

    return client;
  }
}
