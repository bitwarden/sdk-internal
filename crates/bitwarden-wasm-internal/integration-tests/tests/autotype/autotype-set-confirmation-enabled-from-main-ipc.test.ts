import {
  Source,
  autotypeRequestSetConfirmationEnabledFromMain,
  autotypeRequestSetConfirmationEnabledFromRender,
  registerAutotypeMainHandlers,
} from "@bitwarden/sdk-internal";

import {
  makeMockAutotypeMainDriver,
  makeMockAutotypeRenderDriver,
  setupRenderHandlerPair,
} from "./autotype-test-utils";

describe("autotype set-confirmation-enabled-from-main ipc", () => {
  it("reports success when the confirmation dialog is enabled on the render process", async () => {
    const driver = makeMockAutotypeRenderDriver();
    const { main } = await setupRenderHandlerPair(driver);

    const response = await autotypeRequestSetConfirmationEnabledFromMain(main, true);

    expect(response.success).toBe(true);
    expect(driver.confirmationEnabledCalls).toEqual([true]);
  });

  // A successful disable reports `true` — the boolean is whether the change was applied,
  // not the state the setting ended up in.
  it("reports success when the confirmation dialog is disabled on the render process", async () => {
    const driver = makeMockAutotypeRenderDriver();
    const { main } = await setupRenderHandlerPair(driver);

    const response = await autotypeRequestSetConfirmationEnabledFromMain(main, false);

    expect(response.success).toBe(true);
    expect(driver.confirmationEnabledCalls).toEqual([false]);
  });

  it("reports failure when the driver cannot apply the change", async () => {
    const driver = makeMockAutotypeRenderDriver({
      setConfirmationEnabled: async () => false,
    });
    const { main } = await setupRenderHandlerPair(driver);

    const response = await autotypeRequestSetConfirmationEnabledFromMain(main, true);

    expect(response.success).toBe(false);
    expect(driver.confirmationEnabledCalls).toEqual([true]);
  });

  it("reports failure when the driver throws", async () => {
    const driver = makeMockAutotypeRenderDriver({
      setConfirmationEnabled: async () => {
        throw new Error("settings unavailable");
      },
    });
    const { main } = await setupRenderHandlerPair(driver);

    // A throwing driver is never reported as successful, in either direction, and the
    // request resolves rather than rejecting.
    await expect(autotypeRequestSetConfirmationEnabledFromMain(main, true)).resolves.toEqual({
      success: false,
    });
    await expect(autotypeRequestSetConfirmationEnabledFromMain(main, false)).resolves.toEqual({
      success: false,
    });

    expect(driver.confirmationEnabledCalls).toEqual([true, false]);
  });

  it("keeps concurrent changes matched to their own requests", async () => {
    // Succeed on enable and fail on disable, purely so each response is distinguishable —
    // a crossed correlation would surface as a mismatched ordering below.
    const driver = makeMockAutotypeRenderDriver({
      setConfirmationEnabled: async (enabled) => enabled,
    });
    const { main } = await setupRenderHandlerPair(driver);

    const responses = await Promise.all([
      autotypeRequestSetConfirmationEnabledFromMain(main, true),
      autotypeRequestSetConfirmationEnabledFromMain(main, false),
      autotypeRequestSetConfirmationEnabledFromMain(main, true),
    ]);

    expect(responses.map((r) => r.success)).toEqual([true, false, true]);
  });

  // In the real app both processes register their handlers on the same pair, so each side
  // both sends and applies. Each request must reach only the driver on the other side.
  it("runs alongside the render → main channel on the same client pair", async () => {
    const renderDriver = makeMockAutotypeRenderDriver();
    const mainDriver = makeMockAutotypeMainDriver();
    const { main, render } = await setupRenderHandlerPair(renderDriver);
    await registerAutotypeMainHandlers(main, mainDriver);

    // Establish the Noise session before sending concurrently. If both sides send their first
    // message at the same moment, each starts its own handshake and they end up with mismatched
    // sessions — a limitation of `bitwarden-ipc`'s handshake, not of these channels.
    await autotypeRequestSetConfirmationEnabledFromRender(render, true);

    const [fromMain, fromRender] = await Promise.all([
      autotypeRequestSetConfirmationEnabledFromMain(main, true),
      autotypeRequestSetConfirmationEnabledFromRender(render, false),
    ]);

    expect(fromMain).toEqual({ success: true });
    expect(fromRender).toEqual({ success: true });
    expect(renderDriver.confirmationEnabledCalls).toEqual([true]);
    expect(mainDriver.confirmationEnabledCalls).toEqual([true, false]);
  });

  // Main forwards native-messaging traffic to the render process under its original source, labeled
  // the way desktop's `sourceFor()` labels it. Only main itself may change the setting, in
  // either direction.
  it.each<[string, Source]>([
    ["the browser extension", { BrowserBackground: { id: { Id: 1 } } }],
    ["the CLI", { Cli: { id: { Id: 1 } } }],
  ])("refuses a change sent by %s without calling the driver", async (_label, source) => {
    const driver = makeMockAutotypeRenderDriver();
    const { main: peer } = await setupRenderHandlerPair(driver, source);

    await expect(autotypeRequestSetConfirmationEnabledFromMain(peer, true)).resolves.toEqual({
      success: false,
    });
    await expect(autotypeRequestSetConfirmationEnabledFromMain(peer, false)).resolves.toEqual({
      success: false,
    });

    expect(driver.confirmationEnabledCalls).toEqual([]);
  });
});
