import {
  type IncomingMessage,
  type IpcClientSubscription,
  IpcClient,
  init_sdk,
  OutgoingMessage,
  type Source,
} from "@bitwarden/sdk-internal";

import { makeMockTransportPair } from "../utils";

/** Largest payload that fits in one Noise transport message. */
const NOISE_MAX_PAYLOAD = 65535 - 16;
/** Largest payload the IPC client sends or reassembles. */
const MAX_PAYLOAD = 5 * 1024 * 1024;
/** Bounds a receive, so a dropped message fails the test instead of hanging it. */
const RECEIVE_TIMEOUT_MS = 10_000;

const WEB_SOURCE: Source = {
  Web: { tab_id: 1, document_id: "doc", origin: "https://vault.bitwarden.com" },
};

/**
 * `sync` hands each message to the peer within the sender's call. `task` delivers every message in
 * its own macrotask, as browser runtime messaging does.
 */
type Delivery = "sync" | "task";

function makePayload(len: number, seed = 0): Uint8Array {
  const payload = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    payload[i] = (i % 251) ^ seed;
  }
  return payload;
}

function receive(subscription: IpcClientSubscription): Promise<IncomingMessage> {
  return subscription.receive(AbortSignal.timeout(RECEIVE_TIMEOUT_MS));
}

function expectPayload(actual: Uint8Array, expected: Uint8Array) {
  expect(actual.length).toBe(expected.length);
  // Deep equality on megabytes of bytes is slow, so compare as buffers.
  expect(Buffer.from(actual).equals(Buffer.from(expected))).toBe(true);
}

async function setupClientPair(delivery: Delivery, senderSource: Source = "DesktopMain") {
  init_sdk();

  const [senderBackend, receiverBackend, router] = makeMockTransportPair(
    senderSource,
    "DesktopRenderer",
  );
  if (delivery === "task") {
    router.setFirstReceiver((m) => setTimeout(() => senderBackend.receive(m)));
    router.setSecondReceiver((m) => setTimeout(() => receiverBackend.receive(m)));
  }

  const sender = IpcClient.newWithSdkInMemorySessions(senderBackend);
  const receiver = IpcClient.newWithSdkInMemorySessions(receiverBackend);
  await sender.start();
  await receiver.start();
  const subscription = await receiver.subscribe();

  return { sender, subscription };
}

describe.each<Delivery>(["sync", "task"])("ipc fragmentation with %s delivery", (delivery) => {
  it.each([
    ["an empty payload", 0],
    ["the largest single-message payload", NOISE_MAX_PAYLOAD],
    ["the smallest fragmented payload", NOISE_MAX_PAYLOAD + 1],
    ["a 1 MiB payload", 1024 * 1024 + 7],
    ["the largest payload", MAX_PAYLOAD],
  ])("delivers %s unchanged", async (_, len) => {
    const { sender, subscription } = await setupClientPair(delivery);
    const payload = makePayload(len);

    await sender.send(new OutgoingMessage(payload, "DesktopRenderer", "bulk"));

    const received = await receive(subscription);
    expect(received.topic).toBe("bulk");
    expect(received.source).toBe("DesktopMain");
    expectPayload(received.payload, payload);
  });

  it("delivers a fragmented payload without a topic", async () => {
    const { sender, subscription } = await setupClientPair(delivery);
    const payload = makePayload(NOISE_MAX_PAYLOAD * 3);

    await sender.send(new OutgoingMessage(payload, "DesktopRenderer", undefined));

    const received = await receive(subscription);
    expect(received.topic).toBeUndefined();
    expectPayload(received.payload, payload);
  });

  it("reassembles concurrent fragmented sends separately", async () => {
    const { sender, subscription } = await setupClientPair(delivery);
    const first = makePayload(1024 * 1024, 1);
    const second = makePayload(700 * 1024, 2);

    await Promise.all([
      sender.send(new OutgoingMessage(first, "DesktopRenderer", "first")),
      sender.send(new OutgoingMessage(second, "DesktopRenderer", "second")),
    ]);

    const received = [await receive(subscription), await receive(subscription)];
    const byTopic = new Map(received.map((m) => [m.topic, m.payload]));
    expectPayload(byTopic.get("first")!, first);
    expectPayload(byTopic.get("second")!, second);
  });

  it("delivers the largest payload from a web page", async () => {
    const { sender, subscription } = await setupClientPair(delivery, WEB_SOURCE);
    const payload = makePayload(MAX_PAYLOAD, 3);

    await sender.send(new OutgoingMessage(payload, "DesktopRenderer", "bulk"));

    const received = await receive(subscription);
    expect(received.source).toEqual(WEB_SOURCE);
    expectPayload(received.payload, payload);
  });
});

describe("ipc fragmentation limits", () => {
  it("rejects payloads over the maximum", async () => {
    const { sender } = await setupClientPair("sync");

    await expect(
      sender.send(new OutgoingMessage(makePayload(MAX_PAYLOAD + 1), "DesktopRenderer", "bulk")),
    ).rejects.toThrow(/exceeds the maximum/);
  });

  it.each(["IpcFragment", "IpcFragment/bulk"])("rejects the reserved topic %s", async (topic) => {
    const { sender } = await setupClientPair("sync");

    await expect(
      sender.send(new OutgoingMessage(makePayload(16), "DesktopRenderer", topic)),
    ).rejects.toThrow(/reserved/);
  });
});
