import {
  Endpoint,
  IncomingMessage,
  IpcClient,
  IpcCommunicationBackend,
  IpcCommunicationBackendSender,
  OutgoingMessage,
  Source,
  init_sdk,
} from "@bitwarden/sdk-internal";

import { sleep } from "./utils";

const REACHABILITY_PING_TOPIC = "$bitwarden_reachability_ping";
const REACHABILITY_PONG_TOPIC = "$bitwarden_reachability_pong";

/**
 * Wires two IPC clients over a paired in-memory transport, capturing every outgoing message from
 * each side so tests can assert on the reachability ping/pong that the SDK drives itself.
 */
function setupCapturingPair(
  followerSource: Source = "DesktopMain",
  leaderSource: Source = "DesktopRenderer",
) {
  const followerOutgoing: OutgoingMessage[] = [];
  const leaderOutgoing: OutgoingMessage[] = [];

  let receiveOnLeader: (m: IncomingMessage) => void;
  let receiveOnFollower: (m: IncomingMessage) => void;

  const followerSender: IpcCommunicationBackendSender = {
    send: async (outgoing: OutgoingMessage) => {
      followerOutgoing.push(outgoing);
      receiveOnLeader(
        new IncomingMessage(outgoing.payload, outgoing.destination, followerSource, outgoing.topic),
      );
    },
  };
  const leaderSender: IpcCommunicationBackendSender = {
    send: async (outgoing: OutgoingMessage) => {
      leaderOutgoing.push(outgoing);
      receiveOnFollower(
        new IncomingMessage(outgoing.payload, outgoing.destination, leaderSource, outgoing.topic),
      );
    },
  };

  const followerBackend = new IpcCommunicationBackend(followerSender);
  const leaderBackend = new IpcCommunicationBackend(leaderSender);
  receiveOnFollower = (m) => followerBackend.receive(m);
  receiveOnLeader = (m) => leaderBackend.receive(m);

  return { followerBackend, leaderBackend, followerOutgoing, leaderOutgoing, leaderSource };
}

async function waitForReachable(client: IpcClient, endpoint: Endpoint): Promise<boolean> {
  for (let i = 0; i < 50; i++) {
    if (await client.isReachable(endpoint)) {
      return true;
    }
    await sleep(20);
  }
  return false;
}

describe("reachability ipc", () => {
  it("pings the configured leader, which answers with a pong, marking it reachable", async () => {
    init_sdk();

    const { followerBackend, leaderBackend, followerOutgoing, leaderOutgoing, leaderSource } =
      setupCapturingPair();
    // The follower records the leader by the source stamped on inbound frames.
    const leaderEndpoint = leaderSource as Endpoint;

    // The follower pings (and therefore gates) the leader; the leader is a passive responder.
    const follower = IpcClient.newWithSdkInMemorySessions(followerBackend, {
      pingTargets: [leaderEndpoint],
    });
    const leader = IpcClient.newWithSdkInMemorySessions(leaderBackend, { pingTargets: [] });

    // Gated and never seen: the leader starts out unreachable.
    expect(await follower.isReachable(leaderEndpoint)).toBe(false);

    // Start the responder first so it is subscribed before the follower emits its first ping.
    await leader.start();
    await follower.start();

    // The SDK-driven ping/pong round trip should make the leader reachable.
    expect(await waitForReachable(follower, leaderEndpoint)).toBe(true);

    // ...and that round trip is visible on the wire: a ping from the follower, a pong from the leader.
    expect(
      followerOutgoing.some(
        (m) => m.topic === REACHABILITY_PING_TOPIC && m.destination === leaderEndpoint,
      ),
    ).toBe(true);
    expect(leaderOutgoing.some((m) => m.topic === REACHABILITY_PONG_TOPIC)).toBe(true);
  });

  it("answers an inbound ping with a pong even when it pings no one itself", async () => {
    init_sdk();

    const { followerBackend, leaderBackend, leaderOutgoing, leaderSource } = setupCapturingPair();
    const leaderEndpoint = leaderSource as Endpoint;

    const follower = IpcClient.newWithSdkInMemorySessions(followerBackend, {
      pingTargets: [leaderEndpoint],
    });
    // Passive responder: no ping targets, but the SDK still answers inbound pings.
    const responder = IpcClient.newWithSdkInMemorySessions(leaderBackend, { pingTargets: [] });

    await responder.start();
    await follower.start();

    await waitForReachable(follower, leaderEndpoint);

    expect(leaderOutgoing.some((m) => m.topic === REACHABILITY_PONG_TOPIC)).toBe(true);
  });

  it("keeps a gated leader unreachable when nothing answers its pings", async () => {
    init_sdk();

    const leaderEndpoint: Endpoint = "DesktopRenderer";
    // A backend whose sends go nowhere: pings are emitted but never answered.
    const followerBackend = new IpcCommunicationBackend({
      send: async () => {},
    });
    const follower = IpcClient.newWithSdkInMemorySessions(followerBackend, {
      pingTargets: [leaderEndpoint],
    });

    await follower.start();
    // Give the scheduler time to emit unanswered pings.
    await sleep(100);

    expect(await follower.isReachable(leaderEndpoint)).toBe(false);
  });

  it("marks a leader unreachable after invalidateReachability", async () => {
    init_sdk();

    const { followerBackend, leaderBackend, leaderSource } = setupCapturingPair();
    const leaderEndpoint = leaderSource as Endpoint;

    const follower = IpcClient.newWithSdkInMemorySessions(followerBackend, {
      pingTargets: [leaderEndpoint],
    });
    const leader = IpcClient.newWithSdkInMemorySessions(leaderBackend, { pingTargets: [] });

    await leader.start();
    await follower.start();

    expect(await waitForReachable(follower, leaderEndpoint)).toBe(true);

    // A known transport disconnect can be surfaced immediately rather than waiting for the window.
    follower.invalidateReachability(leaderEndpoint);
    expect(await follower.isReachable(leaderEndpoint)).toBe(false);
  });
});
