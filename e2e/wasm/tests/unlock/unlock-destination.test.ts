import {
  BiometricsStatus,
  Endpoint,
  IpcClient,
  IpcCommunicationBackend,
  IpcCommunicationBackendSender,
  IncomingMessage,
  OutgoingMessage,
  Source,
  ipcRegisterBiometricsHandlers,
  ipcRequestGetBiometricsStatus,
  ipcRequestUnlockBiometrics,
  init_sdk,
} from "@bitwarden/sdk-internal";

import { makeMockBiometricsDriver, TEST_USER_ID, testSymmetricKey } from "../utils";

/**
 * A desktop serves biometrics from its main process or its renderer depending on how it is built
 * and configured, so the caller says which when it asks. These check that the destination is
 * honoured, and that each process answers only for itself.
 */

const CLI_SOURCE: Source = { Cli: { id: "Own" } };
const MAIN_KEY = testSymmetricKey(0x11);
const RENDERER_KEY = testSymmetricKey(0x22);

/**
 * A CLI wired to a desktop's two processes, each its own peer with its own biometrics driver, so
 * a request can be told apart by which key comes back.
 */
async function setupDesktop(options: { servedBy?: Endpoint } = {}) {
  init_sdk();

  const addressed: Endpoint[] = [];
  const receive: Partial<Record<"requester" | "main" | "renderer", (m: IncomingMessage) => void>> =
    {};

  const toRequester =
    (source: Source): IpcCommunicationBackendSender => ({
      send: async (outgoing: OutgoingMessage) => {
        receive.requester!(
          new IncomingMessage(outgoing.payload, outgoing.destination, source, outgoing.topic),
        );
      },
    });

  const fromRequester: IpcCommunicationBackendSender = {
    send: async (outgoing: OutgoingMessage) => {
      addressed.push(outgoing.destination);
      const target = outgoing.destination === "DesktopMain" ? receive.main : receive.renderer;
      // A process that is not serving is not there to answer; the send goes nowhere.
      target?.(
        new IncomingMessage(outgoing.payload, outgoing.destination, CLI_SOURCE, outgoing.topic),
      );
    },
  };

  const requesterBackend = new IpcCommunicationBackend(fromRequester);
  const mainBackend = new IpcCommunicationBackend(toRequester("DesktopMain"));
  const rendererBackend = new IpcCommunicationBackend(toRequester("DesktopRenderer"));
  receive.requester = (m) => requesterBackend.receive(m);
  receive.main = (m) => mainBackend.receive(m);
  receive.renderer = (m) => rendererBackend.receive(m);

  const requester = IpcClient.newWithSdkInMemorySessions(requesterBackend);
  const main = IpcClient.newWithSdkInMemorySessions(mainBackend);
  const renderer = IpcClient.newWithSdkInMemorySessions(rendererBackend);
  await requester.start();
  await main.start();
  await renderer.start();

  // Each process answers with a key of its own, so a reply names where it came from.
  const serve = async (peer: IpcClient, userKey: typeof MAIN_KEY) =>
    await ipcRegisterBiometricsHandlers(
      peer,
      makeMockBiometricsDriver({ userKey, uvResult: true, status: BiometricsStatus.Available }),
    );

  const servedBy = options.servedBy;
  if (servedBy == null || servedBy === "DesktopMain") {
    await serve(main, MAIN_KEY);
  }
  if (servedBy == null || servedBy === "DesktopRenderer") {
    await serve(renderer, RENDERER_KEY);
  }

  return { requester, addressed };
}

describe("the unlock destination", () => {
  it("sends to main when main is named", async () => {
    const { requester, addressed } = await setupDesktop();

    const response = await ipcRequestUnlockBiometrics(requester, TEST_USER_ID, "DesktopMain");

    expect(response.user_key).toBe(MAIN_KEY);
    expect(addressed).not.toContain("DesktopRenderer");
  });

  it("sends to the renderer when the renderer is named", async () => {
    const { requester, addressed } = await setupDesktop();

    const response = await ipcRequestUnlockBiometrics(requester, TEST_USER_ID, "DesktopRenderer");

    expect(response.user_key).toBe(RENDERER_KEY);
    expect(addressed).not.toContain("DesktopMain");
  });

  it("carries the destination on a status request too", async () => {
    const { requester, addressed } = await setupDesktop();

    await ipcRequestGetBiometricsStatus(requester, TEST_USER_ID, "DesktopMain");

    // The handshake is addressed the same way, so every send went to main.
    expect(addressed).not.toContain("DesktopRenderer");
    expect(addressed.length).toBeGreaterThan(0);
  });

  it("gets no answer from a process that does not serve biometrics", async () => {
    // Only main serves, which is a desktop whose renderer has been torn down.
    const { requester } = await setupDesktop({ servedBy: "DesktopMain" });

    await expect(
      ipcRequestGetBiometricsStatus(
        requester,
        TEST_USER_ID,
        "DesktopRenderer",
        AbortSignal.timeout(500),
      ),
    ).rejects.toBeDefined();
  });
});
