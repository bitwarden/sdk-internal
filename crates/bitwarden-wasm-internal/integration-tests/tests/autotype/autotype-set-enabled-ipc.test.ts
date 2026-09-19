import {
  AutotypeDriver,
  IpcClient,
  autotypeRegisterSetEnabledHandler,
  autotypeRequestSetEnabled,
  init_sdk,
} from "@bitwarden/sdk-internal";

import { makeMockTransportPair } from "../utils";

/**
 * In-memory implementation of the `AutotypeDriver` JS interface. Records what it
 * was asked to do and reports whether it applied the change, which the tests
 * vary independently of the request to cover a driver that fails.
 */
function makeMockAutotypeDriver(
  setEnabled: (enabled: boolean) => Promise<boolean> = async () => true,
): AutotypeDriver & { calls: boolean[] } {
  const calls: boolean[] = [];

  return {
    calls,
    set_autotype_enabled: async (enabled: boolean) => {
      calls.push(enabled);
      return setEnabled(enabled);
    },
  };
}

/**
 * Builds the desktop pairing the real app uses: a main-process client that owns
 * the global shortcut and a renderer-process client that toggles it, over paired
 * in-memory transports.
 *
 * Only `main` registers the handler, matching the one-directional channel — the
 * renderer sends, main applies.
 */
async function setupClientPair(driver: AutotypeDriver = makeMockAutotypeDriver()) {
  init_sdk();

  const [mainBackend, rendererBackend] = makeMockTransportPair();
  const main = IpcClient.newWithSdkInMemorySessions(mainBackend);
  const renderer = IpcClient.newWithSdkInMemorySessions(rendererBackend);

  await main.start();
  await renderer.start();

  await autotypeRegisterSetEnabledHandler(main, driver);

  return { main, renderer };
}

describe("autotype set-enabled ipc", () => {
  it("reports success when autotype is enabled on the main process", async () => {
    const driver = makeMockAutotypeDriver();
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetEnabled(renderer, true);

    expect(response.success).toBe(true);
    expect(driver.calls).toEqual([true]);
  });

  // A successful disable reports `true` — the boolean is whether the change was applied,
  // not the state autotype ended up in.
  it("reports success when autotype is disabled on the main process", async () => {
    const driver = makeMockAutotypeDriver();
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetEnabled(renderer, false);

    expect(response.success).toBe(true);
    expect(driver.calls).toEqual([false]);
  });

  // The driver reports failure when it cannot apply the change — a `globalShortcut.register()`
  // that returns false, for instance.
  it("reports failure when the driver cannot apply the change", async () => {
    const driver = makeMockAutotypeDriver(async () => false);
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetEnabled(renderer, true);

    expect(response.success).toBe(false);
    expect(driver.calls).toEqual([true]);
  });

  it("reports failure when the driver throws", async () => {
    const driver = makeMockAutotypeDriver(async () => {
      throw new Error("globalShortcut unavailable");
    });
    const { renderer } = await setupClientPair(driver);

    // A throwing driver is never reported as successful, in either direction, and the
    // request resolves rather than rejecting.
    await expect(autotypeRequestSetEnabled(renderer, true)).resolves.toEqual({ success: false });
    await expect(autotypeRequestSetEnabled(renderer, false)).resolves.toEqual({ success: false });

    expect(driver.calls).toEqual([true, false]);
  });

  it("keeps concurrent toggles matched to their own requests", async () => {
    // Succeed on enable and fail on disable, purely so each response is distinguishable —
    // a crossed correlation would surface as a mismatched ordering below.
    const driver = makeMockAutotypeDriver(async (enabled) => enabled);
    const { renderer } = await setupClientPair(driver);

    const responses = await Promise.all([
      autotypeRequestSetEnabled(renderer, true),
      autotypeRequestSetEnabled(renderer, false),
      autotypeRequestSetEnabled(renderer, true),
    ]);

    expect(responses.map((r) => r.success)).toEqual([true, false, true]);
  });
});
