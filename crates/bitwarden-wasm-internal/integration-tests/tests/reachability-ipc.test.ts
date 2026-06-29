import {
  Endpoint,
  IpcClient,
  IpcCommunicationBackend,
  IpcCommunicationBackendSender,
  OutgoingMessage,
  Reachability,
  init_sdk,
} from "@bitwarden/sdk-internal";

import { makeMockTransportPair, sleep } from "./utils";

const PING_TOPIC = "$bw.control.ping";

async function waitForReachable(
  handle: { isReachable(): Promise<boolean> },
  timeoutMs = 1000,
): Promise<boolean> {
  for (let elapsed = 0; elapsed < timeoutMs; elapsed += 20) {
    if (await handle.isReachable()) {
      return true;
    }
    await sleep(20);
  }
  return handle.isReachable();
}

describe("reachability ipc", () => {
  it("pings a leader whose transport does not support reachability and becomes reachable once it pongs", async () => {
    init_sdk();

    // first stamps "DesktopMain", second stamps "DesktopRenderer".
    const [followerBackend, leaderBackend] = makeMockTransportPair();
    const follower = IpcClient.newWithSdkInMemorySessions(followerBackend);
    const leader = IpcClient.newWithSdkInMemorySessions(leaderBackend);

    // Start the responder first so it is listening before the follower's first ping.
    await leader.start();
    await follower.start();

    // The follower sees the leader as the source it stamps on inbound frames.
    const leaderEndpoint: Endpoint = "DesktopRenderer";
    const handle = follower.reachability().track(leaderEndpoint);

    // The mock transport does not implement reachability(), so it answers Unsupported: the leader is
    // gated until the ping/pong round trip lands.
    expect(await handle.isReachable()).toBe(false);
    expect(await waitForReachable(handle)).toBe(true);
  });

  it("never pings a transport that answers Reachable", async () => {
    init_sdk();

    const outgoing: OutgoingMessage[] = [];
    const sender: IpcCommunicationBackendSender = {
      send: async (message: OutgoingMessage) => {
        outgoing.push(message);
      },
      reachability: async (_endpoint: Endpoint): Promise<Reachability> => "Reachable",
    };
    const client = IpcClient.newWithSdkInMemorySessions(new IpcCommunicationBackend(sender));
    await client.start();

    const handle = client.reachability().track("DesktopRenderer");

    // An authoritative Reachable answer is trusted directly, and no ping is ever emitted.
    expect(await handle.isReachable()).toBe(true);
    await sleep(100);
    expect(outgoing.some((m) => m.topic === PING_TOPIC)).toBe(false);
  });

  it("reports Unreachable directly from the transport without pinging", async () => {
    init_sdk();

    const outgoing: OutgoingMessage[] = [];
    const sender: IpcCommunicationBackendSender = {
      send: async (message: OutgoingMessage) => {
        outgoing.push(message);
      },
      reachability: async (_endpoint: Endpoint): Promise<Reachability> => "Unreachable",
    };
    const client = IpcClient.newWithSdkInMemorySessions(new IpcCommunicationBackend(sender));
    await client.start();

    const handle = client.reachability().track("DesktopRenderer");

    expect(await handle.isReachable()).toBe(false);
    await sleep(100);
    expect(outgoing.some((m) => m.topic === PING_TOPIC)).toBe(false);
  });
});
