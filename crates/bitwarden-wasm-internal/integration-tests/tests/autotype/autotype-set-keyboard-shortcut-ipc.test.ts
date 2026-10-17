import {
  autotypeRequestSetEnabled,
  autotypeRequestSetKeyboardShortcut,
} from "@bitwarden/sdk-internal";

import { makeMockAutotypeDriver, setupClientPair } from "./autotype-test-utils";

/** The desktop app's default combination, in the wire shape: modifiers first, base key last. */
const DEFAULT_SHORTCUT = ["Control", "Alt", "B"];

describe("autotype set-keyboard-shortcut ipc", () => {
  it("reports success when the shortcut is applied on the main process", async () => {
    const driver = makeMockAutotypeDriver();
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetKeyboardShortcut(renderer, DEFAULT_SHORTCUT);

    expect(response.success).toBe(true);
    expect(driver.shortcutCalls).toEqual([DEFAULT_SHORTCUT]);
  });

  // The driver reports failure when it cannot apply the shortcut — a combination another
  // application already owns, or one it rejects as malformed.
  it("reports failure when the driver cannot apply the shortcut", async () => {
    const driver = makeMockAutotypeDriver({ setKeyboardShortcut: async () => false });
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetKeyboardShortcut(renderer, ["Alt", "Q"]);

    expect(response.success).toBe(false);
    expect(driver.shortcutCalls).toEqual([["Alt", "Q"]]);
  });

  it("reports failure when the driver throws", async () => {
    const driver = makeMockAutotypeDriver({
      setKeyboardShortcut: async () => {
        throw new Error("globalShortcut unavailable");
      },
    });
    const { renderer } = await setupClientPair(driver);

    // A throwing driver is never reported as successful, and the request resolves rather
    // than rejecting.
    await expect(autotypeRequestSetKeyboardShortcut(renderer, DEFAULT_SHORTCUT)).resolves.toEqual({
      success: false,
    });

    expect(driver.shortcutCalls).toEqual([DEFAULT_SHORTCUT]);
  });

  // The SDK is a transport here: what counts as a usable combination is the receiving client's
  // call, so even nonsense reaches the driver untouched rather than being rejected in Rust.
  it.each([
    ["an empty shortcut", []],
    ["a shortcut with no base key", ["Control", "Alt"]],
    ["a shortcut with an unrecognized key", ["Meta", "BANANA"]],
  ])("forwards %s unchanged", async (_label, shortcut) => {
    const driver = makeMockAutotypeDriver({ setKeyboardShortcut: async () => false });
    const { renderer } = await setupClientPair(driver);

    const response = await autotypeRequestSetKeyboardShortcut(renderer, shortcut);

    expect(response.success).toBe(false);
    expect(driver.shortcutCalls).toEqual([shortcut]);
  });

  it("keeps concurrent shortcut changes matched to their own requests", async () => {
    // Succeed only on three-key combinations, purely so each response is distinguishable —
    // a crossed correlation would surface as a mismatched ordering below.
    const driver = makeMockAutotypeDriver({
      setKeyboardShortcut: async (shortcut) => shortcut.length === 3,
    });
    const { renderer } = await setupClientPair(driver);

    const responses = await Promise.all([
      autotypeRequestSetKeyboardShortcut(renderer, DEFAULT_SHORTCUT),
      autotypeRequestSetKeyboardShortcut(renderer, ["Alt", "Q"]),
      autotypeRequestSetKeyboardShortcut(renderer, ["Control", "Super", "A"]),
    ]);

    expect(responses.map((r) => r.success)).toEqual([true, false, true]);
    expect(driver.shortcutCalls).toEqual([
      DEFAULT_SHORTCUT,
      ["Alt", "Q"],
      ["Control", "Super", "A"],
    ]);
  });

  it("does not block the set-enabled channel while a shortcut change is in flight", async () => {
    let releaseShortcut!: (applied: boolean) => void;
    const shortcutGate = new Promise<boolean>((resolve) => {
      releaseShortcut = resolve;
    });

    const driver = makeMockAutotypeDriver({
      // Stays pending until the test releases it, so the shortcut request is guaranteed to
      // still be in flight below.
      setKeyboardShortcut: () => shortcutGate,
    });
    const { renderer } = await setupClientPair(driver);

    // Capture the shortcut request's settled state without awaiting it, so that if the
    // set-enabled request below were to settle it early, it surfaces as a failed assertion
    // rather than an unhandled rejection.
    const shortcut = autotypeRequestSetKeyboardShortcut(renderer, DEFAULT_SHORTCUT).then(
      (ok) => ({ ok }),
      (err) => ({ err: String(err) }),
    );

    // Both channels share one single-threaded runner backing the same driver instance, so a
    // pending call on one must not stall the other.
    await expect(autotypeRequestSetEnabled(renderer, true)).resolves.toEqual({ success: true });

    releaseShortcut(true);

    expect(await shortcut).toEqual({ ok: { success: true } });
  });
});
