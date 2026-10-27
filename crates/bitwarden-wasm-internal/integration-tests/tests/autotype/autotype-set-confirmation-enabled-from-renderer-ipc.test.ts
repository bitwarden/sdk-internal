import {
  Source,
  autotypeRequestSetConfirmationEnabledFromRenderer,
  autotypeRequestSetEnabled,
} from "@bitwarden/sdk-internal";

import { makeMockAutotypeMainDriver, setupClientPair } from "./autotype-test-utils";

describe("autotype set-confirmation-enabled-from-renderer ipc", () => {
  it("reports success when the confirmation dialog is enabled on the main process", async () => {
    const driver = makeMockAutotypeMainDriver();
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetConfirmationEnabledFromRenderer(renderer, true);

    expect(response.success).toBe(true);
    expect(driver.confirmationEnabledCalls).toEqual([true]);
  });

  // A successful disable reports `true` — the boolean is whether the change was applied,
  // not the state the setting ended up in.
  it("reports success when the confirmation dialog is disabled on the main process", async () => {
    const driver = makeMockAutotypeMainDriver();
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetConfirmationEnabledFromRenderer(renderer, false);

    expect(response.success).toBe(true);
    expect(driver.confirmationEnabledCalls).toEqual([false]);
  });

  it("reports failure when the driver cannot apply the change", async () => {
    const driver = makeMockAutotypeMainDriver({
      setConfirmationEnabled: async () => false,
    });
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetConfirmationEnabledFromRenderer(renderer, true);

    expect(response.success).toBe(false);
    expect(driver.confirmationEnabledCalls).toEqual([true]);
  });

  it("reports failure when the driver throws", async () => {
    const driver = makeMockAutotypeMainDriver({
      setConfirmationEnabled: async () => {
        throw new Error("settings unavailable");
      },
    });
    const { renderer } = await setupClientPair(driver);

    // A throwing driver is never reported as successful, in either direction, and the
    // request resolves rather than rejecting.
    await expect(
      autotypeRequestSetConfirmationEnabledFromRenderer(renderer, true),
    ).resolves.toEqual({ success: false });
    await expect(
      autotypeRequestSetConfirmationEnabledFromRenderer(renderer, false),
    ).resolves.toEqual({ success: false });

    expect(driver.confirmationEnabledCalls).toEqual([true, false]);
  });

  it("keeps concurrent changes matched to their own requests", async () => {
    // Succeed on enable and fail on disable, purely so each response is distinguishable —
    // a crossed correlation would surface as a mismatched ordering below.
    const driver = makeMockAutotypeMainDriver({
      setConfirmationEnabled: async (enabled) => enabled,
    });
    const { renderer } = await setupClientPair(driver);

    const responses = await Promise.all([
      autotypeRequestSetConfirmationEnabledFromRenderer(renderer, true),
      autotypeRequestSetConfirmationEnabledFromRenderer(renderer, false),
      autotypeRequestSetConfirmationEnabledFromRenderer(renderer, true),
    ]);

    expect(responses.map((r) => r.success)).toEqual([true, false, true]);
  });

  it("does not block the set-enabled channel while a change is in flight", async () => {
    let releaseConfirmation!: (applied: boolean) => void;
    const confirmationGate = new Promise<boolean>((resolve) => {
      releaseConfirmation = resolve;
    });

    const driver = makeMockAutotypeMainDriver({
      // Stays pending until the test releases it, so the confirmation request is guaranteed to
      // still be in flight below.
      setConfirmationEnabled: () => confirmationGate,
    });
    const { renderer } = await setupClientPair(driver);

    // Capture the confirmation request's settled state without awaiting it, so that if the
    // set-enabled request below were to settle it early, it surfaces as a failed assertion
    // rather than an unhandled rejection.
    const confirmation = autotypeRequestSetConfirmationEnabledFromRenderer(renderer, true).then(
      (ok) => ({ ok }),
      (err) => ({ err: String(err) }),
    );

    // All channels share one single-threaded runner backing the same driver instance, so a
    // pending call on one must not stall the others.
    await expect(autotypeRequestSetEnabled(renderer, true)).resolves.toEqual({ success: true });

    releaseConfirmation(true);

    expect(await confirmation).toEqual({ ok: { success: true } });
  });

  // Main's IPC client also carries native-messaging peers, labeled the way desktop's
  // `sourceFor()` labels them. Only the renderer may change the setting, in either direction.
  it.each<[string, Source]>([
    ["the browser extension", { BrowserBackground: { id: { Id: 1 } } }],
    ["the CLI", { Cli: { id: { Id: 1 } } }],
  ])("refuses a change sent by %s without calling the driver", async (_label, source) => {
    const driver = makeMockAutotypeMainDriver();
    const { renderer: peer } = await setupClientPair(driver, source);

    await expect(autotypeRequestSetConfirmationEnabledFromRenderer(peer, true)).resolves.toEqual({
      success: false,
    });
    await expect(autotypeRequestSetConfirmationEnabledFromRenderer(peer, false)).resolves.toEqual({
      success: false,
    });

    expect(driver.confirmationEnabledCalls).toEqual([]);
  });
});
