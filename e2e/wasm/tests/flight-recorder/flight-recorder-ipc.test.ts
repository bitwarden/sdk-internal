import type { Endpoint } from "@bitwarden/sdk-internal";

import { ClientContext, type RecordedEvent } from "./client-context";

const MAIN: Endpoint = "DesktopMain";
// Longer than the forwarder's 250 ms flush interval.
const FLUSHED_MS = 600;
// A discover attempt to an unreachable collector times out after 5 s before the next is sent.
const DISCOVER_RETRIED_MS = 6000;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function processOf(events: RecordedEvent[], message: string) {
  const matching = events.filter((e) => e.message === message);
  expect(matching).toHaveLength(1);
  return matching[0].process;
}

function messagesOf(events: RecordedEvent[]) {
  return events.map((e) => e.message);
}

/**
 * Desktop: the main process collects, the renderer forwards. Each runs its own SDK instance; the
 * test relays IPC between them and assigns each message's `Source`, as the Electron transport does.
 */
describe("Flight Recorder aggregation over IPC", () => {
  let main: ClientContext;
  let renderer: ClientContext;

  beforeEach(async () => {
    [main, renderer] = await Promise.all([ClientContext.start(), ClientContext.start()]);
  });

  afterEach(async () => {
    await Promise.all([main.terminate(), renderer.terminate()]);
  });

  function connect() {
    main.sendTo(renderer, "DesktopMain");
    renderer.sendTo(main, "DesktopRenderer");
  }

  async function startCollector() {
    await main.registerDiscoverHandler();
    await main.enableFlightRecorderCollection("DesktopMain");
  }

  it("collects the renderer's events in main, including those logged before forwarding", async () => {
    // 1. The renderer logs before and after it starts forwarding; main logs its own event.
    connect();
    await startCollector();
    await renderer.log("before forwarding");
    await renderer.enableFlightRecorderForwarding(MAIN);
    await sleep(FLUSHED_MS);
    await main.log("main event");
    await renderer.log("after forwarding");
    await sleep(FLUSHED_MS);

    // 2. Verify main holds every event, attributed by the transport-provided source.
    const inMain = await main.readFlightRecorder();
    expect(processOf(inMain, "before forwarding")).toBe("desktop-renderer");
    expect(processOf(inMain, "after forwarding")).toBe("desktop-renderer");
    expect(processOf(inMain, "main event")).toBeUndefined();

    // 3. Verify a read from the renderer returns main's buffer, labelled for export.
    const fromRenderer = await renderer.readFlightRecorder();
    expect(processOf(fromRenderer, "main event")).toBe("desktop-main");
    expect(processOf(fromRenderer, "before forwarding")).toBe("desktop-renderer");
    expect(processOf(fromRenderer, "after forwarding")).toBe("desktop-renderer");
  });

  it("keeps events local until main starts, then forwards them", async () => {
    // 1. Main is unreachable: the renderer's discover requests are dropped.
    main.sendTo(renderer, "DesktopMain");
    await renderer.enableFlightRecorderForwarding(MAIN);
    await renderer.log("before main started");
    await sleep(FLUSHED_MS);
    // Without this check, the final one would also pass if events were forwarded and buffered.
    expect(
      processOf(await renderer.readFlightRecorder(200), "before main started"),
    ).toBeUndefined();

    // 2. Main starts and answers the next discover attempt.
    connect();
    await startCollector();
    await sleep(DISCOVER_RETRIED_MS);

    // 3. Verify the event reached main.
    expect(processOf(await main.readFlightRecorder(), "before main started")).toBe(
      "desktop-renderer",
    );
  }, 20_000);

  it("forwards when main registers its discover handler after the renderer starts forwarding", async () => {
    // 1. Main's IPC client is up but answers discover with an error until its handler is registered.
    connect();
    await main.enableFlightRecorderCollection("DesktopMain");
    await renderer.enableFlightRecorderForwarding(MAIN);
    await sleep(FLUSHED_MS);
    await main.registerDiscoverHandler();
    await renderer.log("after discover handler");
    await sleep(FLUSHED_MS * 2);

    // 2. Verify the renderer kept retrying and forwarded the event.
    expect(processOf(await main.readFlightRecorder(), "after discover handler")).toBe(
      "desktop-renderer",
    );
  });

  it("returns the renderer's unsent events when main stops answering and the read is aborted", async () => {
    // 1. Forwarding starts, then main goes away and the renderer logs.
    connect();
    await startCollector();
    await renderer.enableFlightRecorderForwarding(MAIN);
    await sleep(FLUSHED_MS);
    renderer.disconnect();
    await renderer.log("after main left");

    // 2. Verify the aborted read returns promptly with the unsent event.
    const started = Date.now();
    const events = await renderer.readFlightRecorder(300);
    expect(Date.now() - started).toBeLessThan(2000);
    expect(messagesOf(events)).toContain("after main left");
  });

  it("bounds a read without an abort signal at 5 s when main stops answering", async () => {
    // 1. Forwarding starts, then main goes away.
    connect();
    await startCollector();
    await renderer.enableFlightRecorderForwarding(MAIN);
    await sleep(FLUSHED_MS);
    renderer.disconnect();

    // 2. Verify the read gives up after the default timeout.
    const started = Date.now();
    await renderer.readFlightRecorder();
    const elapsed = Date.now() - started;
    expect(elapsed).toBeGreaterThan(4000);
    expect(elapsed).toBeLessThan(7000);
  }, 15_000);

  it("ignores batches and reads from a source other than its own forwarder", async () => {
    // 1. Main receives the renderer's messages attributed to a browser page instead. Discover
    //    answers any source, so forwarding starts.
    main.sendTo(renderer, "DesktopMain");
    renderer.sendTo(main, { BrowserForeground: { id: 1 } });
    await startCollector();
    await renderer.enableFlightRecorderForwarding(MAIN);
    await sleep(FLUSHED_MS);
    await main.log("main event");
    await renderer.log("injected");
    await sleep(FLUSHED_MS);

    // 2. Verify main stored nothing from that source and served it nothing.
    expect(messagesOf(await main.readFlightRecorder())).not.toContain("injected");
    expect(messagesOf(await renderer.readFlightRecorder())).not.toContain("main event");
  });
});
