import { ClientEmulator } from "./client-emulator/client-emulator";
import { ServerEmulator } from "./server-emulator/server-emulator";

import type { HttpMock } from "./server-emulator/http-mock";

export class TestHarness {
  readonly server = new ServerEmulator();

  // Patches `fetch` to route requests to the server emulator globally.
  private readonly hook: HttpMock = this.server.installFetchHook();

  newClientEmulator(): ClientEmulator {
    return new ClientEmulator(this.server);
  }

  /** Unpatches `fetch`. Call in `afterEach`, or the patch outlives the test. */
  restore(): void {
    this.hook.restore();
  }
}

/** A fresh harness. Call in `beforeEach`. */
export function testHarness(): TestHarness {
  return new TestHarness();
}
