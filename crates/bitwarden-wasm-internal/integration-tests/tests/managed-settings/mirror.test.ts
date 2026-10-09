/**
 * Mirroring a `ManagedSettingsClient` profile from one process to another over `bitwarden-ipc`.
 *
 * Two `IpcClient`s are paired over an in-memory transport, so every message goes through the real
 * serialize, encrypt, decrypt, and deserialize path. Outcomes that leave no other trace are asserted
 * through the flight recorder, which holds the SDK's log events.
 */
import {
  FlightRecorderClient,
  IncomingMessage,
  IpcClient,
  IpcCommunicationBackend,
  ManagedSettingsClient,
  Source,
  init_sdk,
} from "@bitwarden/sdk-internal";

import { makeMockTransportPair, MockTransportRouter } from "../utils";

const BASE_KEY = "environment.base";
const PROFILE_A = JSON.stringify({ environment: { base: "https://a.example.com" } });
const PROFILE_B = JSON.stringify({ environment: { base: "https://b.example.com" } });
const BASE_A = JSON.stringify("https://a.example.com");
const BASE_B = JSON.stringify("https://b.example.com");

/** Matches `PROFILE_REQUEST_TIMEOUT` in `bitwarden-managed-settings/src/mirror.rs`. */
const PROFILE_REQUEST_TIMEOUT_MS = 5000;

interface Pair {
  authority: ManagedSettingsClient;
  mirror: ManagedSettingsClient;
  authorityIpc: IpcClient;
  mirrorIpc: IpcClient;
  authorityBackend: IpcCommunicationBackend;
  router: MockTransportRouter;
}

/**
 * Two started IPC clients, each with its own managed settings client. The authority's messages
 * arrive with `authoritySource`, and the mirror's with `mirrorSource`.
 */
async function makePair(
  authoritySource: Source = "DesktopMain",
  mirrorSource: Source = "DesktopRenderer",
): Promise<Pair> {
  init_sdk();

  const [authorityBackend, mirrorBackend, router] = makeMockTransportPair(
    authoritySource,
    mirrorSource,
  );
  const authorityIpc = IpcClient.newWithSdkInMemorySessions(authorityBackend);
  const mirrorIpc = IpcClient.newWithSdkInMemorySessions(mirrorBackend);
  await authorityIpc.start();
  await mirrorIpc.start();

  return {
    authority: new ManagedSettingsClient(),
    mirror: new ManagedSettingsClient(),
    authorityIpc,
    mirrorIpc,
    authorityBackend,
    router,
  };
}

/** Resolves once `condition` holds, or rejects after `timeoutMs`. */
async function waitFor(condition: () => boolean, timeoutMs = 2000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!condition()) {
    if (Date.now() > deadline) {
      throw new Error("condition not met in time");
    }
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
}

/** Waits long enough for any message in flight on the in-memory transport to be handled. */
function settle(ms = 200): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Number of flight recorder events whose message contains `text`. */
function logCount(text: string): number {
  return new FlightRecorderClient().read().filter((event) => event.message.includes(text)).length;
}

/** Delivers `message` to the authority's IPC client, as the transport normally does. */
function deliverToAuthority(pair: Pair, message: IncomingMessage): void {
  pair.authorityBackend.receive(message);
}

describe("managed settings mirror", () => {
  it("delivers a profile set before the mirror started through the request", async () => {
    const { authority, mirror, authorityIpc, mirrorIpc } = await makePair();
    await authority.update_from_json(PROFILE_A);
    await authority.mirror_to(authorityIpc, "DesktopRenderer");

    await mirror.mirror_from(mirrorIpc, "DesktopMain");

    await waitFor(() => mirror.get(BASE_KEY) === BASE_A);
  });

  it("pushes every later update, and clearing the authority clears the mirror", async () => {
    const { authority, mirror, authorityIpc, mirrorIpc } = await makePair();
    await authority.mirror_to(authorityIpc, "DesktopRenderer");
    await mirror.mirror_from(mirrorIpc, "DesktopMain");
    await settle();

    await authority.update_from_json(PROFILE_A);
    await waitFor(() => mirror.get(BASE_KEY) === BASE_A);

    await authority.update_from_json(PROFILE_B);
    await waitFor(() => mirror.get(BASE_KEY) === BASE_B);

    await authority.update_from_json(undefined);
    await waitFor(() => !mirror.is_managed(BASE_KEY));
  });

  it("clears the mirror when the authority rejects a malformed value", async () => {
    const { authority, mirror, authorityIpc, mirrorIpc } = await makePair();
    await authority.update_from_json(PROFILE_A);
    await authority.mirror_to(authorityIpc, "DesktopRenderer");
    await mirror.mirror_from(mirrorIpc, "DesktopMain");
    await waitFor(() => mirror.get(BASE_KEY) === BASE_A);

    await expect(authority.update_from_json("[1, 2]")).rejects.toMatchObject({
      name: "ManagedSettingsError",
      variant: "NotAnObject",
    });

    await waitFor(() => !mirror.is_managed(BASE_KEY));
  });

  it("drops a request response that arrives after a push was applied", async () => {
    const pair = await makePair();
    const { authority, mirror, authorityIpc, mirrorIpc, router } = pair;
    await authority.mirror_to(authorityIpc, "DesktopRenderer");
    // Completes the session handshake while both directions deliver, so the request below is
    // only a single message that can be held.
    await authority.update_from_json(PROFILE_A);
    await settle();

    const held: IncomingMessage[] = [];
    router.setFirstReceiver((message) => held.push(message));
    const droppedBefore = logCount("Dropped a managed profile response");

    await mirror.mirror_from(mirrorIpc, "DesktopMain");
    await waitFor(() => held.length > 0);

    await authority.update_from_json(PROFILE_B);
    await waitFor(() => mirror.get(BASE_KEY) === BASE_B);

    // The request reaches the authority only now, so its response arrives after the push.
    router.setFirstReceiver((message) => deliverToAuthority(pair, message));
    held.forEach((message) => deliverToAuthority(pair, message));

    await waitFor(() => logCount("Dropped a managed profile response") > droppedBefore);
    expect(mirror.get(BASE_KEY)).toBe(BASE_B);
  });

  it(
    "keeps applying pushes after its request timed out",
    async () => {
      const pair = await makePair();
      const { authority, mirror, authorityIpc, mirrorIpc, router } = pair;
      await authority.mirror_to(authorityIpc, "DesktopRenderer");
      await authority.update_from_json(PROFILE_A);
      await settle();

      const held: IncomingMessage[] = [];
      router.setFirstReceiver((message) => held.push(message));
      const timedOutBefore = logCount("Managed profile request timed out");

      await mirror.mirror_from(mirrorIpc, "DesktopMain");
      await waitFor(
        () => logCount("Managed profile request timed out") > timedOutBefore,
        PROFILE_REQUEST_TIMEOUT_MS + 2000,
      );
      expect(mirror.is_managed(BASE_KEY)).toBe(false);

      // The held request is discarded; the authority never answers it.
      router.setFirstReceiver((message) => deliverToAuthority(pair, message));

      await authority.update_from_json(PROFILE_B);
      await waitFor(() => mirror.get(BASE_KEY) === BASE_B);
    },
    PROFILE_REQUEST_TIMEOUT_MS + 10_000,
  );

  it("rejects a push from a peer that is not its authority", async () => {
    const { authority, mirror, authorityIpc, mirrorIpc, router } = await makePair(
      { Cli: { id: { Id: 7 } } },
      "DesktopRenderer",
    );
    await authority.mirror_to(authorityIpc, "DesktopRenderer");
    // Establishes the session from the other peer's side. The mirror is not subscribed yet, so
    // this push is not delivered to it.
    await authority.update_from_json(PROFILE_A);
    await settle();
    // The in-memory transport would deliver the mirror's request to the other peer whatever its
    // address. Dropping it leaves the request to time out in the background.
    router.setFirstReceiver(() => {});
    await mirror.mirror_from(mirrorIpc, "DesktopMain");
    const rejectedBefore = logCount("Rejected a managed profile push");

    await authority.update_from_json(PROFILE_B);

    await waitFor(() => logCount("Rejected a managed profile push") > rejectedBefore);
    expect(mirror.is_managed(BASE_KEY)).toBe(false);
  });

  it("refuses a request from a peer that is not its destination", async () => {
    const { authority, mirror, authorityIpc, mirrorIpc } = await makePair("DesktopMain", {
      Cli: { id: { Id: 7 } },
    });
    await authority.update_from_json(PROFILE_A);
    await authority.mirror_to(authorityIpc, "DesktopRenderer");
    const refusedBefore = logCount("Refused a managed profile request");
    const notDestinationBefore = logCount("this client is not its destination");

    await mirror.mirror_from(mirrorIpc, "DesktopMain");

    await waitFor(() => logCount("this client is not its destination") > notDestinationBefore);
    expect(logCount("Refused a managed profile request")).toBeGreaterThan(refusedBefore);
    expect(mirror.is_managed(BASE_KEY)).toBe(false);
  });

  it("resolves an update whose push fails, and logs the failure", async () => {
    const { authority, authorityIpc, router } = await makePair();
    await authority.mirror_to(authorityIpc, "DesktopRenderer");
    router.setSecondReceiver(() => {
      throw new Error("renderer unreachable");
    });
    const failedBefore = logCount("Failed to push the managed profile");

    await authority.update_from_json(PROFILE_A);

    expect(authority.get(BASE_KEY)).toBe(BASE_A);
    expect(logCount("Failed to push the managed profile")).toBeGreaterThan(failedBefore);
  });

  it("notifies a change subscriber when the mirror applies a profile", async () => {
    const { authority, mirror, authorityIpc, mirrorIpc } = await makePair();
    await authority.mirror_to(authorityIpc, "DesktopRenderer");
    await mirror.mirror_from(mirrorIpc, "DesktopMain");
    await settle();
    const seen: (string | undefined)[] = [];
    const abort = new AbortController();
    mirror.on_profile_changed(() => seen.push(mirror.get(BASE_KEY)), abort.signal);

    await authority.update_from_json(PROFILE_A);

    await waitFor(() => seen.includes(BASE_A));
    abort.abort();
  });
});
