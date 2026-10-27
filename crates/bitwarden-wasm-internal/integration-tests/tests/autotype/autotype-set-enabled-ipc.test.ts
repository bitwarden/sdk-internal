import { Source, autotypeRequestSetEnabled } from "@bitwarden/sdk-internal";

import { makeMockAutotypeMainDriver, setupClientPair } from "./autotype-test-utils";

describe("autotype set-enabled ipc", () => {
  it("reports success when autotype is enabled on the main process", async () => {
    const driver = makeMockAutotypeMainDriver();
    const { render } = await setupClientPair(driver);

    const response = await autotypeRequestSetEnabled(render, true);

    expect(response.success).toBe(true);
    expect(driver.enabledCalls).toEqual([true]);
  });

  // A successful disable reports `true` — the boolean is whether the change was applied,
  // not the state autotype ended up in.
  it("reports success when autotype is disabled on the main process", async () => {
    const driver = makeMockAutotypeMainDriver();
    const { render } = await setupClientPair(driver);

    const response = await autotypeRequestSetEnabled(render, false);

    expect(response.success).toBe(true);
    expect(driver.enabledCalls).toEqual([false]);
  });

  // The driver reports failure when it cannot apply the change — a `globalShortcut.register()`
  // that returns false, for instance.
  it("reports failure when the driver cannot apply the change", async () => {
    const driver = makeMockAutotypeMainDriver({ setEnabled: async () => false });
    const { render } = await setupClientPair(driver);

    const response = await autotypeRequestSetEnabled(render, true);

    expect(response.success).toBe(false);
    expect(driver.enabledCalls).toEqual([true]);
  });

  it("reports failure when the driver throws", async () => {
    const driver = makeMockAutotypeMainDriver({
      setEnabled: async () => {
        throw new Error("globalShortcut unavailable");
      },
    });
    const { render } = await setupClientPair(driver);

    // A throwing driver is never reported as successful, in either direction, and the
    // request resolves rather than rejecting.
    await expect(autotypeRequestSetEnabled(render, true)).resolves.toEqual({ success: false });
    await expect(autotypeRequestSetEnabled(render, false)).resolves.toEqual({ success: false });

    expect(driver.enabledCalls).toEqual([true, false]);
  });

  it("keeps concurrent toggles matched to their own requests", async () => {
    // Succeed on enable and fail on disable, purely so each response is distinguishable —
    // a crossed correlation would surface as a mismatched ordering below.
    const driver = makeMockAutotypeMainDriver({ setEnabled: async (enabled) => enabled });
    const { render } = await setupClientPair(driver);

    const responses = await Promise.all([
      autotypeRequestSetEnabled(render, true),
      autotypeRequestSetEnabled(render, false),
      autotypeRequestSetEnabled(render, true),
    ]);

    expect(responses.map((r) => r.success)).toEqual([true, false, true]);
  });

  // Main's IPC client also carries native-messaging peers, labeled the way desktop's
  // `sourceFor()` labels them. Only the render process may toggle autotype, in either direction.
  it.each<[string, Source]>([
    ["the browser extension", { BrowserBackground: { id: { Id: 1 } } }],
    ["the CLI", { Cli: { id: { Id: 1 } } }],
  ])("refuses a toggle sent by %s without calling the driver", async (_label, source) => {
    const driver = makeMockAutotypeMainDriver();
    const { render: peer } = await setupClientPair(driver, source);

    await expect(autotypeRequestSetEnabled(peer, true)).resolves.toEqual({ success: false });
    await expect(autotypeRequestSetEnabled(peer, false)).resolves.toEqual({ success: false });

    expect(driver.enabledCalls).toEqual([]);
  });
});
