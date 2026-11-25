import {
  IpcClient,
  IpcCommunicationBackend,
  IpcCommunicationBackendSender,
  IncomingMessage,
  OutgoingMessage,
  BiometricsStatus,
  BiometricsUnlock,
  SymmetricKey,
  UserId,
  ipcRegisterBiometricsHandlers,
  ipcRequestAuthenticateBiometrics,
  ipcRequestUnlockBiometrics,
  init_sdk,
} from "@bitwarden/sdk-internal";
import {
  makeMockTransportPair,
  makeMockBiometricsDriver,
  testSymmetricKey,
  TEST_USER_ID,
} from "../utils";

/**
 * Boundary behavior of the IPC framework, exercised across the real Rust/WASM/JS divide (these
 * cannot be reproduced by the native Rust tests, which run on multi-threaded tokio rather than the
 * single-threaded wasm executor with non-Send JS objects).
 */
describe("IpcClient", () => {
  describe("request", () => {
    it("returns each response to its own request when many requests are in flight concurrently", async () => {
      init_sdk();
      const [requesterBackend, responderBackend] = makeMockTransportPair();
      const requester = IpcClient.newWithSdkInMemorySessions(requesterBackend);
      const responder = IpcClient.newWithSdkInMemorySessions(responderBackend);
      await requester.start();
      await responder.start();

      const N = 12;
      const users: UserId[] = Array.from(
        { length: N },
        (_, i) => `00000000-0000-0000-0000-${String(i).padStart(12, "0")}` as unknown as UserId,
      );
      const keyForUser = new Map<string, SymmetricKey>();
      users.forEach((u, i) => keyForUser.set(String(u), testSymmetricKey(i + 1)));

      const driver: BiometricsUnlock = {
        get_biometrics_status: async () => BiometricsStatus.Available,
        unlock_biometrics: async (userId: UserId) => keyForUser.get(String(userId)),
        authenticate_biometrics: async () => true,
      };
      await ipcRegisterBiometricsHandlers(responder, driver);

      const responses = await Promise.all(
        users.map((u) => ipcRequestUnlockBiometrics(requester, u)),
      );

      responses.forEach((response, i) => {
        expect(response.user_key).toBe(keyForUser.get(String(users[i])));
      });
    });

    it("completes a later request when an earlier send throws", async () => {
      init_sdk();

      let requesterReceive!: (m: IncomingMessage) => void;
      let responderReceive!: (m: IncomingMessage) => void;
      let throwOnce = true;

      const requesterSender: IpcCommunicationBackendSender = {
        send: async (out: OutgoingMessage) => {
          if (throwOnce) {
            throwOnce = false;
            throw new Error("transient send failure");
          }
          responderReceive(
            new IncomingMessage(out.payload, out.destination, "DesktopMain", out.topic),
          );
        },
      };
      const responderSender: IpcCommunicationBackendSender = {
        send: async (out: OutgoingMessage) => {
          requesterReceive(
            new IncomingMessage(out.payload, out.destination, "DesktopRenderer", out.topic),
          );
        },
      };

      const requesterBackend = new IpcCommunicationBackend(requesterSender);
      const responderBackend = new IpcCommunicationBackend(responderSender);
      requesterReceive = (m) => requesterBackend.receive(m);
      responderReceive = (m) => responderBackend.receive(m);

      const requester = IpcClient.newWithSdkInMemorySessions(requesterBackend);
      const responder = IpcClient.newWithSdkInMemorySessions(responderBackend);
      await requester.start();
      await responder.start();
      await ipcRegisterBiometricsHandlers(responder, makeMockBiometricsDriver());

      // First request: the handshake's initial send throws, so the request fails but the client survives.
      await expect(
        ipcRequestAuthenticateBiometrics(requester, AbortSignal.timeout(2000)),
      ).rejects.toBeDefined();
      expect(requester.isRunning()).toBe(true);

      // Second request: the send works now, so it must succeed.
      expect(await ipcRequestAuthenticateBiometrics(requester, AbortSignal.timeout(5000))).toBe(
        true,
      );
    });

    it("rejects a pending request when its abort signal fires", async () => {
      init_sdk();
      const [requesterBackend, responderBackend] = makeMockTransportPair();
      const requester = IpcClient.newWithSdkInMemorySessions(requesterBackend);
      const responder = IpcClient.newWithSdkInMemorySessions(responderBackend);
      await requester.start();
      await responder.start();

      const driver: BiometricsUnlock = {
        get_biometrics_status: async () => BiometricsStatus.Available,
        // Never resolves, so the request stays in flight until the abort signal cancels it.
        unlock_biometrics: () => new Promise<SymmetricKey | undefined>(() => {}),
        authenticate_biometrics: async () => true,
      };
      await ipcRegisterBiometricsHandlers(responder, driver);

      const startedAt = Date.now();
      await expect(
        ipcRequestUnlockBiometrics(requester, TEST_USER_ID, AbortSignal.timeout(300)),
      ).rejects.toBeDefined();
      expect(Date.now() - startedAt).toBeLessThan(2000);
      expect(requester.isRunning()).toBe(true);
    });
  });

  describe("send", () => {
    it("keeps the client running when the transport reports the destination is unreachable", async () => {
      init_sdk();
      const backend = new IpcCommunicationBackend({
        send: async () => {
          throw new Error("Destination unreachable");
        },
      });
      const client = IpcClient.newWithSdkInMemorySessions(backend);
      await client.start();

      await expect(
        client.send(new OutgoingMessage(new Uint8Array([1, 2, 3]), "DesktopRenderer", undefined)),
      ).rejects.toBeDefined();
      expect(client.isRunning()).toBe(true);
    });
  });
});
