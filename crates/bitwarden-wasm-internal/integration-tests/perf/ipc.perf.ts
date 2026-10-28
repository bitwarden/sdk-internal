// Performance harness: one IPC message between two clients through the WASM boundary.
//
//   send ──► split ──► Noise encrypt ──► transport ──► Noise decrypt ──► reassemble ──► receive
//
// Times a send and the matching receive over an established Noise session; the warmup run
// performs the handshake. Two transports:
//   sync  hands each message to the peer within the sender's call, so timings cover the SDK only.
//   task  delivers each message in its own macrotask (`setImmediate`), as browser runtime
//         messaging does, so timings include the scheduling between fragments.
//
// A third group times a small message sent while a 5 MiB send is in flight, which shows whether
// small messages wait for the whole transfer or interleave with its fragments.
//
// Env:
//   PERF_IPC_RUNS  timed runs per case                                (default 20)
//   PERF_LABEL     writes perf/results/<label>/ipc-<case>.json when set

import { strictEqual } from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";

import {
  type IncomingMessage,
  init_sdk,
  IpcClient,
  type IpcClientSubscription,
  OutgoingMessage,
} from "@bitwarden/sdk-internal";
import { beforeAll, test } from "vitest";

import { makeMockTransportPair } from "../tests/utils";

import { benchOptions, runOptions } from "./bench";

const RUNS = Number(process.env.PERF_IPC_RUNS ?? 20);
/** Largest payload that fits in one Noise transport message. */
const NOISE_MAX_PAYLOAD = 65535 - 16;
const MiB = 1024 * 1024;

const SIZES: { name: string; len: number }[] = [
  { name: "1KiB", len: 1024 },
  { name: "single-message-max", len: NOISE_MAX_PAYLOAD },
  { name: "two-fragments", len: NOISE_MAX_PAYLOAD + 1 },
  { name: "1MiB", len: MiB },
  { name: "5MiB", len: 5 * MiB },
];

type Delivery = "sync" | "task";

beforeAll(() => init_sdk());

async function setupClientPair(delivery: Delivery) {
  const [senderBackend, receiverBackend, router] = makeMockTransportPair();
  if (delivery === "task") {
    router.setFirstReceiver((m) => setImmediate(() => senderBackend.receive(m)));
    router.setSecondReceiver((m) => setImmediate(() => receiverBackend.receive(m)));
  }
  const sender = IpcClient.newWithSdkInMemorySessions(senderBackend);
  const receiver = IpcClient.newWithSdkInMemorySessions(receiverBackend);
  await sender.start();
  await receiver.start();
  const subscription = await receiver.subscribe();
  return { sender, subscription };
}

function receive(subscription: IpcClientSubscription): Promise<IncomingMessage> {
  return subscription.receive(AbortSignal.timeout(10_000));
}

for (const delivery of ["sync", "task"] as const) {
  test.for(SIZES)(`ipc ${delivery} $name`, async ({ name, len }, { bench }) => {
    const { sender, subscription } = await setupClientPair(delivery);
    const payload = new Uint8Array(len).fill(0x5a);
    const task = `${delivery}-${name}`;

    // The assertion guards against silently measuring a dropped message.
    await bench(task, benchOptions(`ipc-${task}`), async () => {
      await sender.send(new OutgoingMessage(payload, "DesktopRenderer", "bulk"));
      const received = await receive(subscription);
      strictEqual(received.payload.length, len);
    }).run(runOptions(`ipc ${task}, ${RUNS} runs`, RUNS));
  });
}

// vitest bench times the whole function, which here includes draining the large message, so
// this case times the small message itself and reports its own statistics.
test.for(["sync", "task"] as const)(
  "ipc %s small message during a 5 MiB send",
  async (delivery) => {
    const { sender, subscription } = await setupClientPair(delivery);
    const large = new Uint8Array(5 * MiB).fill(0x5a);
    const small = new Uint8Array(1024).fill(0xa5);

    const latencies: number[] = [];
    // The first run is a warmup that also performs the handshake.
    for (let run = 0; run <= RUNS; run++) {
      const largeSent = sender.send(new OutgoingMessage(large, "DesktopRenderer", "large"));
      const start = performance.now();
      await sender.send(new OutgoingMessage(small, "DesktopRenderer", "small"));
      const topics: (string | undefined)[] = [];
      for (;;) {
        const received = await receive(subscription);
        topics.push(received.topic);
        if (received.topic === "small") {
          break;
        }
      }
      const latency = performance.now() - start;
      await largeSent;
      if (!topics.includes("large")) {
        strictEqual((await receive(subscription)).topic, "large");
      }
      if (run > 0) {
        latencies.push(latency);
      }
    }

    reportLatencies(`${delivery}-small-during-large`, latencies);
  },
);

/** Prints latency statistics, and writes them to `perf/results/<LABEL>/` when set. */
function reportLatencies(task: string, latencies: number[]) {
  const sorted = [...latencies].sort((a, b) => a - b);
  const at = (q: number) => sorted[Math.min(sorted.length - 1, Math.floor(q * sorted.length))];
  const stats = {
    task,
    samples: sorted.length,
    min: sorted[0],
    mean: sorted.reduce((sum, v) => sum + v, 0) / sorted.length,
    p50: at(0.5),
    p99: at(0.99),
    max: sorted[sorted.length - 1],
  };
  console.table([stats]);
  const label = process.env.PERF_LABEL;
  if (label) {
    mkdirSync(`perf/results/${label}`, { recursive: true });
    writeFileSync(`perf/results/${label}/ipc-${task}.json`, JSON.stringify(stats, null, 2));
  }
}
