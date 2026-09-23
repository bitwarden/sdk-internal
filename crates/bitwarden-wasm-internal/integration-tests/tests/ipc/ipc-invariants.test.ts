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
 * Boundary invariants for the IPC framework, exercised across the real Rust/WASM/JS divide (these
 * cannot be reproduced by the native Rust tests, which run on multi-threaded tokio rather than the
 * single-threaded wasm executor with non-Send JS objects).
 */
describe("ipc framework invariants (wasm boundary)", () => {
  // INVARIANT (delivery + correlation, across the boundary): many concurrent requests each receive
  // exactly their own response, even when responses carry distinct per-request payloads.
  it("delivers each of many concurrent requests its own response", async () => {
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

    const responses = await Promise.all(users.map((u) => ipcRequestUnlockBiometrics(requester, u)));

    responses.forEach((response, i) => {
      expect(response.user_key).toBe(keyForUser.get(String(users[i])));
    });
  });

  // INVARIANT (robustness): a JS send that throws is a recoverable failure — the failing request is
  // rejected, the client keeps running, and a subsequent request succeeds. Exercises the
  // ThreadBoundRunner + WasmCommunicationError::Js recoverable path.
  it("keeps serving after a JS send throws, and recovers on the next request", async () => {
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

    // First request: the handshake's initial send throws, so the request fails.
    await expect(
      ipcRequestAuthenticateBiometrics(requester, AbortSignal.timeout(2000)),
    ).rejects.toBeDefined();
    expect(requester.isRunning()).toBe(true);

    // Second request: the send works now, so it must succeed.
    expect(await ipcRequestAuthenticateBiometrics(requester, AbortSignal.timeout(5000))).toBe(true);
  });

  // INVARIANT (error classification): a JS transport that reports "Destination unreachable" is a
  // non-fatal condition — the request is rejected but the client keeps running.
  it("treats a JS 'Destination unreachable' send as non-fatal", async () => {
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

  // INVARIANT (lifetime/cancellation): a pending request whose AbortSignal fires is cancelled
  // promptly rather than hanging, and cancelling it leaves the client running.
  it("cancels a pending request when its AbortSignal fires, and stays running", async () => {
    init_sdk();
    const [requesterBackend, responderBackend] = makeMockTransportPair();
    const requester = IpcClient.newWithSdkInMemorySessions(requesterBackend);
    const responder = IpcClient.newWithSdkInMemorySessions(responderBackend);
    await requester.start();
    await responder.start();

    const driver: BiometricsUnlock = {
      get_biometrics_status: async () => BiometricsStatus.Available,
      // Never resolves, so the request stays in flight until the AbortSignal cancels it.
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
