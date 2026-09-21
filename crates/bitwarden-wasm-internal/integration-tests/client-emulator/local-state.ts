import type {
  Cipher,
  ClientSettings,
  Folder,
  InitUserCryptoMethod,
  PasswordManagerClient,
  Repository,
} from "@bitwarden/sdk-internal";

import { asOrganizationId, asUnsignedSharedKey, asUserId } from "../tests/type-assertion-helpers";
import { makePasswordManagerClient, makeStateBridge } from "../tests/utils";

import { API_URL, IDENTITY_URL } from "../server-emulator/urls";

/** Points the SDK at the server emulator. Nothing listens; every request is served by the fetch mock. */
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

/**
 * Who this state belongs to.
 *
 * A real client reads these off the sync response's profile; the key material next to them comes
 * from the SDK's crypto sync handler, not from here.
 */
export interface LocalIdentity {
  userId: string;
  email: string;
}

export class LocalState {
  readonly bridge = makeStateBridge();
  readonly ciphers = new TestRepository<Cipher>();
  readonly folders = new TestRepository<Folder>();

  /** Organization keys sealed to this account, keyed by organization id. */
  organizationKeys: Record<string, string> = {};

  private identity: LocalIdentity | undefined;

  /** Who this state belongs to. Throws before a sync has recorded it. */
  get account(): LocalIdentity {
    if (this.identity === undefined) {
      throw new Error("local state has no account; sync one down first");
    }

    return this.identity;
  }

  setIdentity(identity: LocalIdentity): void {
    this.identity = identity;
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

  /**
   * A client on this state with no user crypto initialized — what a locked app holds.
   *
   * The repositories are registered here rather than at unlock: a real client wires them up when it
   * starts, not when the vault opens.
   */
  locked(): PasswordManagerClient {
    const client = makePasswordManagerClient(this.bridge, SETTINGS, this.account.userId);

    client.platform().state().register_client_managed_repositories({
      cipher: this.ciphers,
      folder: this.folders,
      local_user_data_key_state: null,
      organization_shared_key: null,
      send: null,
    });

    return client;
  }

  /**
   * Brings a client up on this state and unlocks it with `method`.
   *
   * The KDF settings, cryptographic state and upgrade token are read back out of the bridge, which
   * is where the crypto sync handler put them. Nothing is passed in behind the SDK's back.
   */
  async unlock(method: InitUserCryptoMethod): Promise<PasswordManagerClient> {
    const { userId, email } = this.account;

    const accountCryptographicState = await this.bridge.get_account_cryptographic_state();
    const kdfParams = await this.bridge.get_kdf_config();
    if (accountCryptographicState === null || kdfParams === null) {
      throw new Error(`local state for ${email} has no synced key material`);
    }

    const upgradeToken = await this.bridge.get_v2_upgrade_token();

    const client = this.locked();

    await client.crypto().initialize_user_crypto({
      userId: asUserId(userId),
      email,
      kdfParams,
      accountCryptographicState,
      method,
      ...(upgradeToken === null ? {} : { upgradeToken }),
    });

    const sealedOrganizationKeys = Object.entries(this.organizationKeys);
    if (sealedOrganizationKeys.length > 0) {
      await client.crypto().initialize_org_crypto({
        organizationKeys: new Map(
          sealedOrganizationKeys.map(([id, key]) => [
            asOrganizationId(id),
            asUnsignedSharedKey(key),
          ]),
        ),
      });
    }

    return client;
  }
}
