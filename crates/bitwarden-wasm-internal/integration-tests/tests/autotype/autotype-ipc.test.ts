import {
  IpcClient,
  autotypeRegisterEchoHandler,
  autotypeRequestEcho,
  init_sdk,
} from "@bitwarden/sdk-internal";

import { makeMockTransportPair } from "../utils";

/**
 * Builds the desktop pairing the real app uses: a main-process client and a
 * renderer-process client over paired in-memory transports.
 *
 * Both register the echo handler, matching `MainDesktopAutotypeService` and
 * `DesktopAutotypeService` in the clients repo, so either direction can be
 * requested.
 */
async function setupClientPair() {
  init_sdk();

  const [mainBackend, rendererBackend] = makeMockTransportPair();
  const main = IpcClient.newWithSdkInMemorySessions(mainBackend);
  const renderer = IpcClient.newWithSdkInMemorySessions(rendererBackend);

  await main.start();
  await renderer.start();

  await autotypeRegisterEchoHandler(main);
  await autotypeRegisterEchoHandler(renderer);

  return { main, renderer };
}

describe("autotype ipc", () => {
  it("echoes a message from the main process to the renderer", async () => {
    const { main } = await setupClientPair();

    const response = await autotypeRequestEcho(main, "DesktopRenderer", "hello renderer");

    expect(response.message).toBe("hello renderer");
  });

  it("echoes a message from the renderer to the main process", async () => {
    // The direction the clients implementation exercises automatically at startup,
    // because the renderer initializes last and so cannot lose a race with main.
    const { renderer } = await setupClientPair();

    const response = await autotypeRequestEcho(renderer, "DesktopMain", "hello main");

    expect(response.message).toBe("hello main");
  });

  it("echoes an empty message", async () => {
    const { main } = await setupClientPair();

    const response = await autotypeRequestEcho(main, "DesktopRenderer", "");

    expect(response.message).toBe("");
  });

  it("keeps concurrent echoes matched to their own requests", async () => {
    const { main } = await setupClientPair();

    const responses = await Promise.all([
      autotypeRequestEcho(main, "DesktopRenderer", "first"),
      autotypeRequestEcho(main, "DesktopRenderer", "second"),
      autotypeRequestEcho(main, "DesktopRenderer", "third"),
    ]);

    expect(responses.map((r) => r.message)).toEqual(["first", "second", "third"]);
  });
});
