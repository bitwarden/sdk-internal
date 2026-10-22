// Memory harness: WASM memory growth while two IPC clients exchange a burst of large messages.
//
//   send ──► receive  (x PERF_IPC_BURST, every message read by a subscriber)
//
// WASM linear memory never shrinks, so its growth over the burst is the peak memory the SDK needed.
// Node counts WASM memory in `external` but not in `arrayBuffers`, so their difference excludes the
// JS copies of the payloads. Vitest runs each harness file in its own process, so earlier harnesses
// cannot have grown the memory already; this file holds a single case for the same reason.
//
// The SDK hands each outgoing message (one per fragment) to the transport, and a WASM-owned message
// holds its memory until `free()` or garbage collection, which WASM memory pressure does not
// trigger. PERF_IPC_FREE=1 makes the transport free them; without it, the transport keeps them like
// a client that relies on garbage collection. Received messages are always freed after reading.
//
// Env:
//   PERF_IPC_BURST     messages in the burst                             (default 60)
//   PERF_IPC_BURST_MB  MiB per message                                   (default 1)
//   PERF_IPC_FREE      the transport frees outgoing messages when set to 1
//   PERF_LABEL         writes perf/results/<label>/ipc-memory.json when set

import { strictEqual } from "node:assert/strict";
import { mkdirSync, writeFileSync } from "node:fs";

import {
  IncomingMessage,
  init_sdk,
  IpcClient,
  IpcCommunicationBackend,
  OutgoingMessage,
  type Source,
} from "@bitwarden/sdk-internal";
import { test } from "vitest";

const BURST = Number(process.env.PERF_IPC_BURST ?? 60);
const MESSAGE_LEN = Number(process.env.PERF_IPC_BURST_MB ?? 1) * 1024 * 1024;
const MiB = 1024 * 1024;
const FREE = process.env.PERF_IPC_FREE === "1";

/** WASM memory plus other non-ArrayBuffer external memory, in bytes. */
function wasmMemory(): number {
  const { external, arrayBuffers } = process.memoryUsage();
  return external - arrayBuffers;
}

test("ipc memory after a burst of large messages", async () => {
  init_sdk();
  // A transport pair like `makeMockTransportPair`, which can also free the outgoing messages. Plain
  // object messages have no `free`.
  const backends: IpcCommunicationBackend[] = [];
  const deliverTo = (peer: number, source: Source) => async (message: OutgoingMessage) => {
    const incoming = new IncomingMessage(
      message.payload,
      message.destination,
      source,
      message.topic,
    );
    if (FREE && "free" in message) {
      message.free();
    }
    backends[peer].receive(incoming);
  };
  const senderBackend = new IpcCommunicationBackend({ send: deliverTo(1, "DesktopMain") });
  const receiverBackend = new IpcCommunicationBackend({ send: deliverTo(0, "DesktopRenderer") });
  backends.push(senderBackend, receiverBackend);
  const sender = IpcClient.newWithSdkInMemorySessions(senderBackend);
  const receiver = IpcClient.newWithSdkInMemorySessions(receiverBackend);
  await sender.start();
  await receiver.start();
  const subscription = await receiver.subscribe();
  const payload = new Uint8Array(MESSAGE_LEN).fill(0x5a);

  // One small message performs the handshake before the baseline is taken.
  await sender.send(new OutgoingMessage(new Uint8Array(16), "DesktopRenderer", "warmup"));
  await subscription.receive(AbortSignal.timeout(10_000));
  const before = wasmMemory();

  for (let i = 0; i < BURST; i++) {
    await sender.send(new OutgoingMessage(payload, "DesktopRenderer", "bulk"));
    const received = await subscription.receive(AbortSignal.timeout(10_000));
    strictEqual(received.payload.length, MESSAGE_LEN);
    received.free();
  }

  const growth = wasmMemory() - before;
  const stats = {
    task: "ipc-memory",
    freed: FREE,
    messages: BURST,
    messageMiB: MESSAGE_LEN / MiB,
    growthMiB: Number((growth / MiB).toFixed(1)),
    growthInMessages: Number((growth / MESSAGE_LEN).toFixed(1)),
  };
  console.table([stats]);
  const label = process.env.PERF_LABEL;
  if (label) {
    mkdirSync(`perf/results/${label}`, { recursive: true });
    writeFileSync(
      `perf/results/${label}/ipc-memory${FREE ? "-freed" : ""}.json`,
      JSON.stringify(stats, null, 2),
    );
  }
});
