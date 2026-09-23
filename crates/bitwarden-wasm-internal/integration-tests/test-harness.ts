import type { ClientSettings, LoginRequest } from "@bitwarden/sdk-internal";

import { ClientEmulator, LOGIN_REQUEST } from "./client-emulator/client-emulator";
import { SETTINGS } from "./client-emulator/local-state";
import { ServerEmulator } from "./server-emulator/server-emulator";

import type { HttpMock } from "./server-emulator/http-mock";

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
