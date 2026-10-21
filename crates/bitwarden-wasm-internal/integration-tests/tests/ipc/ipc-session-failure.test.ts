import {
  IpcClient,
  IpcCommunicationBackend,
  IpcSessionRepository,
  ipcRequestGetBiometricsStatus,
  init_sdk,
} from "@bitwarden/sdk-internal";
import { TEST_USER_ID } from "../utils";

/**
 * DOCUMENTED GAP (boundary counterpart of the native `#[ignore]` test
 * `session_store_failure_surfaces_error_instead_of_crashing`).
 *
 * This case is SKIPPED because running it traps the wasm module and cannot be observed cleanly by
 * jest. Empirical behavior (probe, 2026-09-22): when a client-managed session store rejects,
 * NoiseCryptoProvider `.expect()`s the error at crypto_provider.rs:212 and panics; in wasm the panic
 * becomes `RuntimeError: unreachable` and the in-flight request Promise NEVER settles (the request's
 * own AbortSignal does not cancel it). So a failing client-managed session store both wedges the
 * request and traps the module.
 *
 * The body below is the executable spec of the desired behavior. Un-skip it once the session-store
 * `.expect()`s are replaced with error propagation, at which point it should pass.
 */
describe("IpcClient", () => {
  describe("with a client-managed session store", () => {
    it.skip("rejects the request instead of trapping the module when the session store rejects", async () => {
      init_sdk();
      const backend = new IpcCommunicationBackend({ send: async () => {} });
      const failingSessions: IpcSessionRepository = {
        get: async () => {
          throw new Error("session store unavailable");
        },
        save: async () => {
          throw new Error("session store unavailable");
        },
        remove: async () => {
          throw new Error("session store unavailable");
        },
      };
      const client = IpcClient.newWithClientManagedSessions(backend, failingSessions);
      await client.start();

      await expect(
        ipcRequestGetBiometricsStatus(client, TEST_USER_ID, AbortSignal.timeout(2000)),
      ).rejects.toBeDefined();
      expect(client.isRunning()).toBe(true);
    });
  });
});
