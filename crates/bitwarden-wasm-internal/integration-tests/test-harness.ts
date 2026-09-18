import { ClientEmulator } from "./client-emulator/client-emulator";
import { ServerEmulator } from "./server-emulator/server-emulator";

import type { HttpMock } from "./server-emulator/http-mock";
import { primaryUnlockMethod, toSeedAccount, type UserVector } from "./vectors/load";

import type { InitUserCryptoMethod } from "@bitwarden/sdk-internal";

export class TestHarness {
  readonly server = new ServerEmulator();

  // Patches `fetch` to route requests to the server emulator globally.
  private readonly hook: HttpMock = this.server.installFetchHook();

  newClientEmulator(): ClientEmulator {
    return new ClientEmulator(this.server);
  }

  /**
   * Seeds a vector into the server, logs a fresh client in and unlocks it.
   */
  async loadVectorAndUnlock(
    vector: UserVector,
    method?: InitUserCryptoMethod,
  ): Promise<ClientEmulator> {
    const { email } = this.server.seedUser(toSeedAccount(vector));

    const client = this.newClientEmulator();
    await client.login(email);
    await client.unlockWith(method ?? primaryUnlockMethod(vector));

    return client;
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
