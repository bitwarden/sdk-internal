// One client context with its own SDK instance, driven by `ClientContext` in the parent thread.
// The parent delivers IPC messages and assigns each one's `Source`.
import { parentPort } from "node:worker_threads";

import {
  FlightRecorderClient,
  IncomingMessage,
  IpcClient,
  IpcCommunicationBackend,
  LogLevel,
  enableFlightRecorderCollection,
  enableFlightRecorderForwarding,
  init_sdk,
  ipcRegisterDiscoverHandler,
} from "@bitwarden/sdk-internal";

init_sdk(LogLevel.Error);

const backend = new IpcCommunicationBackend({
  send: async (out) => {
    parentPort.postMessage({
      kind: "ipc",
      payload: out.payload,
      destination: out.destination,
      topic: out.topic,
    });
  },
});
const client = IpcClient.newWithSdkInMemorySessions(backend);
const recorder = new FlightRecorderClient();

const commands = {
  start: () => client.start(),
  registerDiscoverHandler: () => ipcRegisterDiscoverHandler(client, { version: "e2e" }),
  enableCollection: ({ role }) => enableFlightRecorderCollection(client, role),
  enableForwarding: ({ destination }) => enableFlightRecorderForwarding(client, destination),
  log: ({ message }) => recorder.write(Date.now(), LogLevel.Info, "e2e", message),
  read: async ({ abortAfterMs }) => {
    const signal = abortAfterMs === undefined ? undefined : AbortSignal.timeout(abortAfterMs);
    const events = await recorder.read(signal);
    return events.map(({ message, process }) => ({ message, process }));
  },
};

parentPort.on("message", async (msg) => {
  if (msg.kind === "ipc") {
    backend.receive(new IncomingMessage(msg.payload, msg.destination, msg.source, msg.topic));
    return;
  }
  try {
    const result = await commands[msg.cmd](msg);
    parentPort.postMessage({ kind: "reply", id: msg.id, result });
  } catch (error) {
    parentPort.postMessage({ kind: "reply", id: msg.id, error: String(error) });
  }
});
