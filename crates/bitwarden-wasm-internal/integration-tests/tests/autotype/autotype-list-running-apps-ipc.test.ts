import {
  AutotypeRunningApp,
  Source,
  autotypeRequestListRunningApps,
  autotypeRequestSetEnabled,
} from "@bitwarden/sdk-internal";

import { makeMockAutotypeMainDriver, setupClientPair } from "./autotype-test-utils";

const RUNNING_APPS: AutotypeRunningApp[] = [
  { name: "Google Chrome", path: "%LOCALAPPDATA%\\Google\\Chrome\\Application\\chrome.exe" },
  { name: "Notepad", path: "C:\\Windows\\System32\\notepad.exe" },
];

describe("autotype list-running-apps ipc", () => {
  it("round-trips the list the main process reports", async () => {
    const driver = makeMockAutotypeMainDriver({ listRunningApps: async () => RUNNING_APPS });
    const { render } = await setupClientPair(driver);

    const response = await autotypeRequestListRunningApps(render);

    // Compared by value, not identity — these crossed a serialize/encrypt/decrypt/deserialize
    // round trip, so this also pins that neither field is dropped or reordered.
    expect(response.apps).toEqual(RUNNING_APPS);
    expect(driver.listRunningAppsCalls).toBe(1);
  });

  it("round-trips an empty list", async () => {
    const driver = makeMockAutotypeMainDriver({ listRunningApps: async () => [] });
    const { render } = await setupClientPair(driver);

    const response = await autotypeRequestListRunningApps(render);

    expect(response.apps).toEqual([]);
    expect(driver.listRunningAppsCalls).toBe(1);
  });

  it("reports an empty list when the driver throws", async () => {
    const driver = makeMockAutotypeMainDriver({
      listRunningApps: async () => {
        throw new Error("autotype is not supported on this platform");
      },
    });
    const { render } = await setupClientPair(driver);

    // The request resolves rather than rejecting — an unavailable driver must not surface as a
    // rejected promise in the render process.
    await expect(autotypeRequestListRunningApps(render)).resolves.toEqual({ apps: [] });
  });

  // Entries are deserialized one at a time, so an unreadable process costs the caller that entry
  // and nothing else. Truncation beats emptiness for what this feeds: a picker missing one obscure
  // process is still usable, one missing every process is not.
  it("skips entries it cannot read and keeps the rest", async () => {
    const driver = makeMockAutotypeMainDriver({
      listRunningApps: async () => [{ name: "Notepad" }, ...RUNNING_APPS],
    });
    const { render } = await setupClientPair(driver);

    const response = await autotypeRequestListRunningApps(render);

    expect(response.apps).toEqual(RUNNING_APPS);
  });

  it.each([
    ["is missing a field", [{ name: "Notepad" }]],
    ["has a non-string field", [{ name: "Notepad", path: 42 }]],
  ])("reports an empty list when the only entry %s", async (_label, payload) => {
    const driver = makeMockAutotypeMainDriver({ listRunningApps: async () => payload });
    const { render } = await setupClientPair(driver);

    const response = await autotypeRequestListRunningApps(render);

    expect(response.apps).toEqual([]);
  });

  // Here the payload itself is unusable rather than any one entry, so there is nothing to salvage.
  it.each([
    ["the payload is not an array", { name: "Notepad", path: "notepad.exe" }],
    ["the payload is null", null],
    ["the payload is undefined", undefined],
  ])("reports an empty list when %s", async (_label, payload) => {
    const driver = makeMockAutotypeMainDriver({ listRunningApps: async () => payload });
    const { render } = await setupClientPair(driver);

    const response = await autotypeRequestListRunningApps(render);

    expect(response.apps).toEqual([]);
  });

  it("dispatches concurrent list requests in the order they were made", async () => {
    // This request carries no arguments, so unlike its set-enabled and set-shortcut siblings there
    // is nothing in a response that identifies which request produced it. A per-call counter is the
    // only discriminator available, which makes this an ordering assertion rather than a
    // correlation one — those two channels cover correlation through this same code path.
    let call = 0;
    const driver = makeMockAutotypeMainDriver({
      listRunningApps: async () => [{ name: `App ${++call}`, path: `app-${call}.exe` }],
    });
    const { render } = await setupClientPair(driver);

    const responses = await Promise.all([
      autotypeRequestListRunningApps(render),
      autotypeRequestListRunningApps(render),
      autotypeRequestListRunningApps(render),
    ]);

    expect(responses.map((r) => r.apps[0].name)).toEqual(["App 1", "App 2", "App 3"]);
    expect(driver.listRunningAppsCalls).toBe(3);
  });

  it("does not block the set-enabled channel while a list request is in flight", async () => {
    let releaseList!: (apps: AutotypeRunningApp[]) => void;
    const listGate = new Promise<AutotypeRunningApp[]>((resolve) => {
      releaseList = resolve;
    });

    const driver = makeMockAutotypeMainDriver({
      // Stays pending until the test releases it, so the list request is guaranteed to still be
      // in flight below.
      listRunningApps: () => listGate,
    });
    const { render } = await setupClientPair(driver);

    // Capture the list request's settled state without awaiting it, so that if the set-enabled
    // request below were to settle it early, it surfaces as a failed assertion rather than an
    // unhandled rejection.
    const list = autotypeRequestListRunningApps(render).then(
      (ok) => ({ ok }),
      (err) => ({ err: String(err) }),
    );

    // All three channels share one single-threaded runner backing the same driver instance, so a
    // pending call on one must not stall the others.
    await expect(autotypeRequestSetEnabled(render, true)).resolves.toEqual({ success: true });

    releaseList(RUNNING_APPS);

    expect(await list).toEqual({ ok: { apps: RUNNING_APPS } });
  });

  // Main's IPC client also carries native-messaging peers, labeled the way desktop's
  // `sourceFor()` labels them. The driver has apps to report, so an empty list can only come
  // from the refusal, and the driver is never asked to enumerate.
  it.each<[string, Source]>([
    ["the browser extension", { BrowserBackground: { id: { Id: 1 } } }],
    ["the CLI", { Cli: { id: { Id: 1 } } }],
  ])("refuses a list request sent by %s without calling the driver", async (_label, source) => {
    const driver = makeMockAutotypeMainDriver({ listRunningApps: async () => RUNNING_APPS });
    const { render: peer } = await setupClientPair(driver, source);

    await expect(autotypeRequestListRunningApps(peer)).resolves.toEqual({ apps: [] });

    expect(driver.listRunningAppsCalls).toBe(0);
  });
});
