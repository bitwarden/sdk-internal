import type { ClientSettings, LoginRequest } from "@bitwarden/sdk-internal";

import { ClientEmulator, LOGIN_REQUEST, LoginMethod } from "./client-emulator/client-emulator";
import { SETTINGS } from "./client-emulator/local-state";
import { describeLoginFailure, liveConfig } from "./live/config";
import { SeederClient, type SeederConfig } from "./live/seeder";
import {
  ServerEmulator,
  type SeedAccount,
  type SeededTestVector,
} from "./server-emulator/server-emulator";
import {
  hasMasterPassword,
  toSeedAccount,
  type MasterPasswordUserVector,
  type UserVector,
} from "./vectors/load";

import type { HttpMock } from "./server-emulator/http-mock";
import type { SeededVector as SeederResult } from "./live/seeder";

/** A user vector seeded on either backend. */
export interface SeededVector<V extends UserVector = UserVector> {
  userId: string;
  email: string;
  vector: V;
  /** What the account decrypts to, for `validateVault`, under the ids the server gave the items. */
  seed: SeedAccount;
}

/**
 * The backend a test runs against: either the emulator, or a real server over the network.
 */
export class TestHarness {
  private readonly emulator: ServerEmulator | undefined;

  // Patches `fetch` to route requests to the server emulator globally. Absent in live mode.
  private readonly hook: HttpMock | undefined;

  /** Seeds a real server from test vectors. Present in live mode when a seeder is configured. */
  readonly seeder: SeederClient | undefined;

  private constructor(
    private readonly settings: ClientSettings,
    private readonly loginRequest: LoginRequest,
    emulated: boolean,
    seeder?: SeederConfig,
  ) {
    if (!emulated) {
      this.seeder = seeder === undefined ? undefined : new SeederClient(seeder);
      return;
    }

    this.emulator = new ServerEmulator();
    this.hook = this.emulator.installFetchHook();
  }

  /** A harness over the server emulator. */
  static emulated(): TestHarness {
    return new TestHarness(SETTINGS, LOGIN_REQUEST, true);
  }

  /** A harness over a real server, reached over the network, seeded through `seeder` if given. */
  static live(
    settings: ClientSettings,
    loginRequest: LoginRequest,
    seeder?: SeederConfig,
  ): TestHarness {
    return new TestHarness(settings, loginRequest, false, seeder);
  }

  /**
   * The emulated backend, for seeding and for assertions on what the server holds.
   *
   * Throws in live mode: a real server has neither, and a test that quietly fell through to an
   * empty emulator would pass while proving nothing.
   */
  get server(): ServerEmulator {
    if (this.emulator === undefined) {
      throw new Error("no server emulator in live mode: seed and inspect through the client");
    }

    return this.emulator;
  }

  /**
   * Seeds a committed user vector: into the emulator, or uploaded unchanged to the live server's
   * seeder. Throws in live mode without a seeder.
   */
  async seedUserTestVector<V extends UserVector>(vector: V): Promise<SeededVector<V>> {
    if (this.emulator !== undefined) {
      const seeded = this.emulator.seedUserTestVector(vector);

      return { userId: String(seeded.userId), email: seeded.email, vector, seed: seeded.seed };
    }

    if (this.seeder === undefined) {
      throw new Error("no seeder in live mode: set BW_LIVE_SEEDER_URL to seed test vectors");
    }

    const seeded = await this.seeder.seedUserVector(vector);

    return {
      userId: seeded.userId,
      email: seeded.email,
      vector,
      seed: withSeededIds(toSeedAccount(vector), seeded),
    };
  }

  newClientEmulator(): ClientEmulator {
    return new ClientEmulator(this.settings, this.emulator, this.loginRequest);
  }

  /**
   * A new device, logged in to `seeded` and unlocked with the vector's first unlock method.
   *
   * Only password login is implemented; TDE and Key Connector accounts skip authentication.
   */
  async newUnlockedClient(seeded: SeededTestVector): Promise<ClientEmulator> {
    const { email, vector } = seeded;
    const client = this.newClientEmulator();

    if (hasMasterPassword(vector)) {
      await client.login(email, LoginMethod.Password, vector.account.password);
    } else {
      await client.login(email, LoginMethod.Unimplemented);
    }
    await client.unlockWith(vector.unlockMethods[0]);

    return client;
  }

  /**
   * Unpatches `fetch`, and removes what the seeder seeded. Call in `afterEach`, or the patch
   * outlives the test.
   */
  async restore(): Promise<void> {
    this.hook?.restore();
    await this.seeder?.cleanup();
  }
}

/** A fresh harness over the server emulator. Call in `beforeEach`. */
export function testHarness(): TestHarness {
  return TestHarness.emulated();
}

/** A fresh harness over a real server. Call in `beforeEach`. */
export function liveHarness(
  settings: ClientSettings,
  loginRequest: LoginRequest,
  seeder?: SeederConfig,
): TestHarness {
  return TestHarness.live(settings, loginRequest, seeder);
}

/** The backend a test that runs on either one is pointed at, for its name. */
export const TARGET = liveConfig() === undefined ? "emulator" : "live server";

/**
 * A fresh harness over the live server when `BW_LIVE_SERVER_URL` is set, and over the emulator
 * otherwise. Call in `beforeEach`.
 */
export function targetHarness(): TestHarness {
  const live = liveConfig();

  return live === undefined
    ? testHarness()
    : liveHarness(live.settings, live.loginRequest, live.seeder);
}

/** An account a test can open any number of sessions on. */
export interface TargetAccount {
  email: string;
  password: string;
  newClient(): ClientEmulator;
}

/**
 * The account a test uses on `harness`: `vector`, seeded into the emulator or through the live
 * server's seeder, or else the configured live account. A live login that fails says what the
 * account needs, since the SDK can't tell why.
 */
export async function targetAccount(
  harness: TestHarness,
  vector: MasterPasswordUserVector,
): Promise<TargetAccount> {
  const live = liveConfig();
  if (live === undefined) {
    const seeded = await harness.seedUserTestVector(vector);

    return {
      email: seeded.email,
      password: vector.account.password,
      newClient: () => harness.newClientEmulator(),
    };
  }

  const { email, password } =
    harness.seeder === undefined
      ? (live.account ?? missingAccount())
      : {
          email: (await harness.seedUserTestVector(vector)).email,
          password: vector.account.password,
        };

  return {
    email,
    password,
    newClient: () => {
      const client = harness.newClientEmulator();
      const login = client.login.bind(client);
      client.login = async (...args) => {
        try {
          await login(...args);
        } catch (error) {
          throw new Error(describeLoginFailure(error));
        }
      };

      return client;
    },
  };
}

function missingAccount(): never {
  throw new Error("live mode has neither a seeder nor an account configured");
}

/** The seed account a vector produces, with the ids the seeder gave its account and items. */
function withSeededIds(seed: SeedAccount, seeded: SeederResult): SeedAccount {
  const cipherId = (id: string) => seeded.cipherIds[id] ?? id;
  const folderId = (id: string) => seeded.folderIds[id] ?? id;

  return {
    ...seed,
    account: { ...seed.account, userId: seeded.userId as never, email: seeded.email },
    vault: {
      ciphers: seed.vault?.ciphers?.map((cipher) => ({
        ...cipher,
        id: cipherId(cipher.id),
        encrypted: {
          ...cipher.encrypted,
          id: cipherId(cipher.id) as never,
          folderId: cipher.encrypted.folderId
            ? (folderId(String(cipher.encrypted.folderId)) as never)
            : undefined,
        },
        decrypted: cipher.decrypted && {
          ...cipher.decrypted,
          id: cipherId(cipher.id) as never,
          folderId: cipher.decrypted.folderId
            ? (folderId(String(cipher.decrypted.folderId)) as never)
            : undefined,
        },
      })),
      folders: seed.vault?.folders?.map((folder) => ({
        ...folder,
        id: folderId(folder.id),
        encrypted: { ...folder.encrypted, id: folderId(folder.id) as never },
        decrypted: folder.decrypted && { ...folder.decrypted, id: folderId(folder.id) as never },
      })),
    },
  };
}
