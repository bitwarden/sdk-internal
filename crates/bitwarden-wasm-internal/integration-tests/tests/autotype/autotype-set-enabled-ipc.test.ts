import { autotypeRequestSetEnabled } from "@bitwarden/sdk-internal";

import { makeMockAutotypeDriver, setupClientPair } from "./autotype-test-utils";

describe("autotype set-enabled ipc", () => {
  it("reports success when autotype is enabled on the main process", async () => {
    const driver = makeMockAutotypeDriver();
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetEnabled(renderer, true);

    expect(response.success).toBe(true);
    expect(driver.enabledCalls).toEqual([true]);
  });

  // A successful disable reports `true` — the boolean is whether the change was applied,
  // not the state autotype ended up in.
  it("reports success when autotype is disabled on the main process", async () => {
    const driver = makeMockAutotypeDriver();
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetEnabled(renderer, false);

    expect(response.success).toBe(true);
    expect(driver.enabledCalls).toEqual([false]);
  });

  // The driver reports failure when it cannot apply the change — a `globalShortcut.register()`
  // that returns false, for instance.
  it("reports failure when the driver cannot apply the change", async () => {
    const driver = makeMockAutotypeDriver({ setEnabled: async () => false });
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetEnabled(renderer, true);

    expect(response.success).toBe(false);
    expect(driver.enabledCalls).toEqual([true]);
  });

  it("reports failure when the driver throws", async () => {
    const driver = makeMockAutotypeDriver({
      setEnabled: async () => {
        throw new Error("globalShortcut unavailable");
      },
    });
    const { renderer } = await setupClientPair(driver);

    // A throwing driver is never reported as successful, in either direction, and the
    // request resolves rather than rejecting.
    await expect(autotypeRequestSetEnabled(renderer, true)).resolves.toEqual({ success: false });
    await expect(autotypeRequestSetEnabled(renderer, false)).resolves.toEqual({ success: false });

    expect(driver.enabledCalls).toEqual([true, false]);
  });

  it("keeps concurrent toggles matched to their own requests", async () => {
    // Succeed on enable and fail on disable, purely so each response is distinguishable —
    // a crossed correlation would surface as a mismatched ordering below.
    const driver = makeMockAutotypeDriver({ setEnabled: async (enabled) => enabled });
    const { renderer } = await setupClientPair(driver);

    const responses = await Promise.all([
      autotypeRequestSetEnabled(renderer, true),
      autotypeRequestSetEnabled(renderer, false),
      autotypeRequestSetEnabled(renderer, true),
    ]);

    expect(responses.map((r) => r.success)).toEqual([true, false, true]);
  });
});
