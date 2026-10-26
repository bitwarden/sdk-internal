import {
  Source,
  autotypeRequestSetConfirmationEnabledFromMain,
  autotypeRequestSetConfirmationEnabledFromRenderer,
  registerAutotypeHandlers,
} from "@bitwarden/sdk-internal";

import {
  makeMockAutotypeDriver,
  makeMockAutotypeRendererDriver,
  setupRendererHandlerPair,
} from "./autotype-test-utils";

describe("autotype set-confirmation-enabled-from-main ipc", () => {
  it("reports success when the confirmation dialog is enabled on the render process", async () => {
    const driver = makeMockAutotypeRendererDriver();
    const { main } = await setupRendererHandlerPair(driver);

    const response = await autotypeRequestSetConfirmationEnabledFromMain(main, true);

    expect(response.success).toBe(true);
    expect(driver.confirmationEnabledFromMainCalls).toEqual([true]);
  });

  // A successful disable reports `true` — the boolean is whether the change was applied,
  // not the state the setting ended up in.
  it("reports success when the confirmation dialog is disabled on the render process", async () => {
    const driver = makeMockAutotypeRendererDriver();
    const { main } = await setupRendererHandlerPair(driver);

    const response = await autotypeRequestSetConfirmationEnabledFromMain(main, false);

    expect(response.success).toBe(true);
    expect(driver.confirmationEnabledFromMainCalls).toEqual([false]);
  });

  it("reports failure when the driver cannot apply the change", async () => {
    const driver = makeMockAutotypeRendererDriver({
      setConfirmationEnabledFromMain: async () => false,
    });
    const { main } = await setupRendererHandlerPair(driver);

    const response = await autotypeRequestSetConfirmationEnabledFromMain(main, true);

    expect(response.success).toBe(false);
    expect(driver.confirmationEnabledFromMainCalls).toEqual([true]);
  });

  it("reports failure when the driver throws", async () => {
    const driver = makeMockAutotypeRendererDriver({
      setConfirmationEnabledFromMain: async () => {
        throw new Error("settings unavailable");
      },
    });
    const { main } = await setupRendererHandlerPair(driver);

    // A throwing driver is never reported as successful, in either direction, and the
    // request resolves rather than rejecting.
    await expect(autotypeRequestSetConfirmationEnabledFromMain(main, true)).resolves.toEqual({
      success: false,
    });
    await expect(autotypeRequestSetConfirmationEnabledFromMain(main, false)).resolves.toEqual({
      success: false,
    });

    expect(driver.confirmationEnabledFromMainCalls).toEqual([true, false]);
  });

  it("keeps concurrent changes matched to their own requests", async () => {
    // Succeed on enable and fail on disable, purely so each response is distinguishable —
    // a crossed correlation would surface as a mismatched ordering below.
    const driver = makeMockAutotypeRendererDriver({
      setConfirmationEnabledFromMain: async (enabled) => enabled,
    });
    const { main } = await setupRendererHandlerPair(driver);

    const responses = await Promise.all([
      autotypeRequestSetConfirmationEnabledFromMain(main, true),
      autotypeRequestSetConfirmationEnabledFromMain(main, false),
      autotypeRequestSetConfirmationEnabledFromMain(main, true),
    ]);

    expect(responses.map((r) => r.success)).toEqual([true, false, true]);
  });

  // In the real app both processes register their handlers on the same pair, so each side
  // both sends and applies. Each request must reach only the driver on the other side.
  it("runs alongside the renderer → main channel on the same client pair", async () => {
    const rendererDriver = makeMockAutotypeRendererDriver();
    const mainDriver = makeMockAutotypeDriver();
    const { main, renderer } = await setupRendererHandlerPair(rendererDriver);
    await registerAutotypeHandlers(main, mainDriver);

    // Establish the Noise session before sending concurrently. If both sides send their first
    // message at the same moment, each starts its own handshake and they end up with mismatched
    // sessions — a limitation of `bitwarden-ipc`'s handshake, not of these channels.
    await autotypeRequestSetConfirmationEnabledFromRenderer(renderer, true);

    const [fromMain, fromRenderer] = await Promise.all([
      autotypeRequestSetConfirmationEnabledFromMain(main, true),
      autotypeRequestSetConfirmationEnabledFromRenderer(renderer, false),
    ]);

    expect(fromMain).toEqual({ success: true });
    expect(fromRenderer).toEqual({ success: true });
    expect(rendererDriver.confirmationEnabledFromMainCalls).toEqual([true]);
    expect(mainDriver.confirmationEnabledFromRendererCalls).toEqual([true, false]);
  });

  // Main forwards native-messaging traffic to the renderer under its original source, labeled
  // the way desktop's `sourceFor()` labels it. Only main itself may change the setting, in
  // either direction.
  it.each<[string, Source]>([
    ["the browser extension", { BrowserBackground: { id: { Id: 1 } } }],
    ["the CLI", { Cli: { id: { Id: 1 } } }],
  ])("refuses a change sent by %s without calling the driver", async (_label, source) => {
    const driver = makeMockAutotypeRendererDriver();
    const { main: peer } = await setupRendererHandlerPair(driver, source);

    await expect(autotypeRequestSetConfirmationEnabledFromMain(peer, true)).resolves.toEqual({
      success: false,
    });
    await expect(autotypeRequestSetConfirmationEnabledFromMain(peer, false)).resolves.toEqual({
      success: false,
    });

    expect(driver.confirmationEnabledFromMainCalls).toEqual([]);
  });
});
