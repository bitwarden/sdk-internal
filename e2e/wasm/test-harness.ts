import type { ClientSettings, LoginRequest } from "@bitwarden/sdk-internal";

import { ClientEmulator, LOGIN_REQUEST, LoginMethod } from "./client-emulator/client-emulator";
import { SETTINGS } from "./client-emulator/local-state";
import { describeLoginFailure, liveConfig } from "./live/config";
import { ServerEmulator, type SeededTestVector } from "./server-emulator/server-emulator";
import { hasMasterPassword } from "./vectors/load";

import type { HttpMock } from "./server-emulator/http-mock";
import type { MasterPasswordUserVector } from "./vectors/load";

/**
 * The backend a test runs against: either the emulator, or a real server over the network.
 */
export class TestHarness {
  private readonly emulator: ServerEmulator | undefined;

  // Patches `fetch` to route requests to the server emulator globally. Absent in live mode.
  private readonly hook: HttpMock | undefined;

  private constructor(
    private readonly settings: ClientSettings,
    private readonly loginRequest: LoginRequest,
    emulated: boolean,
  ) {
    if (!emulated) {
      return;
    }

    this.emulator = new ServerEmulator();
    this.hook = this.emulator.installFetchHook();
  }

  /** A harness over the server emulator. */
  static emulated(): TestHarness {
    return new TestHarness(SETTINGS, LOGIN_REQUEST, true);
  }

  /** A harness over a real server, reached over the network. */
  static live(settings: ClientSettings, loginRequest: LoginRequest): TestHarness {
    return new TestHarness(settings, loginRequest, false);
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

  /** Unpatches `fetch`. Call in `afterEach`, or the patch outlives the test. */
  restore(): void {
    this.hook?.restore();
  }
}

/** A fresh harness over the server emulator. Call in `beforeEach`. */
export function testHarness(): TestHarness {
  return TestHarness.emulated();
}

/** A fresh harness over a real server. Call in `beforeEach`. */
export function liveHarness(settings: ClientSettings, loginRequest: LoginRequest): TestHarness {
  return TestHarness.live(settings, loginRequest);
}

/** The backend a test that runs on either one is pointed at, for its name. */
export const TARGET = liveConfig() === undefined ? "emulator" : "live server";

/**
 * A fresh harness over the live server when `BW_LIVE_SERVER_URL` is set, and over the emulator
 * otherwise. Call in `beforeEach`.
 */
export function targetHarness(): TestHarness {
  const live = liveConfig();

  return live === undefined ? testHarness() : liveHarness(live.settings, live.loginRequest);
}

/** An account a test can open any number of sessions on. */
export interface TargetAccount {
  email: string;
  password: string;
  newClient(): ClientEmulator;
}

/**
 * The account a test uses on `harness`: `vector` seeded into the emulator, or the configured live
 * account. A live login that fails says what the account needs, since the SDK can't tell why.
 */
export function targetAccount(
  harness: TestHarness,
  vector: MasterPasswordUserVector,
): TargetAccount {
  const live = liveConfig();
  if (live === undefined) {
    const seeded = harness.server.seedUserTestVector(vector);

    return {
      email: seeded.email,
      password: seeded.vector.account.password,
      newClient: () => harness.newClientEmulator(),
    };
  }

  return {
    email: live.email,
    password: live.password,
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
