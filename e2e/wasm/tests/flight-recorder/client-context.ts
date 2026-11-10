import { Worker } from "node:worker_threads";

import type { Endpoint, FlightRecorderCollectorRole, Source } from "@bitwarden/sdk-internal";

export type RecordedEvent = { message: string; process?: string };

type IpcMessage = { payload: Uint8Array; destination: Endpoint; topic?: string };

/**
 * A client context (desktop main, renderer, ...) running its own SDK instance in a worker thread.
 * The Flight Recorder is global to a wasm instance, so contexts sharing one would share a buffer.
 */
export class ClientContext {
  private readonly worker = new Worker(new URL("./client-context-worker.mjs", import.meta.url));
  private nextId = 0;
  private readonly calls = new Map<
    number,
    { resolve: (v: any) => void; reject: (e: Error) => void }
  >();
  /** Delivers this context's outgoing IPC messages. Messages are dropped while unset. */
  private deliver?: (msg: IpcMessage) => void;

  private constructor() {
    this.worker.on("message", (msg) => {
      if (msg.kind === "ipc") {
        this.deliver?.(msg);
        return;
      }
      const call = this.calls.get(msg.id)!;
      this.calls.delete(msg.id);
      msg.error === undefined ? call.resolve(msg.result) : call.reject(new Error(msg.error));
    });
  }

  /** Create a context with its IPC client started. */
  static async start(): Promise<ClientContext> {
    const context = new ClientContext();
    await context.call("start");
    return context;
  }

  /** Deliver this context's IPC messages to `to`, attributed by the transport to `source`. */
  sendTo(to: ClientContext, source: Source) {
    this.deliver = (msg) => to.worker.postMessage({ ...msg, kind: "ipc", source });
  }

  /** Drop this context's outgoing IPC messages, as if its peer went away. */
  disconnect() {
    this.deliver = undefined;
  }

  registerDiscoverHandler() {
    return this.call("registerDiscoverHandler");
  }

  enableFlightRecorderCollection(role: FlightRecorderCollectorRole) {
    return this.call("enableCollection", { role });
  }

  enableFlightRecorderForwarding(destination: Endpoint) {
    return this.call("enableForwarding", { destination });
  }

  /** Write an event through `FlightRecorderClient.write`. */
  log(message: string) {
    return this.call("log", { message });
  }

  /** `FlightRecorderClient.read`, with an abort signal firing after `abortAfterMs` if given. */
  readFlightRecorder(abortAfterMs?: number) {
    return this.call<RecordedEvent[]>("read", { abortAfterMs });
  }

  terminate() {
    return this.worker.terminate();
  }

  private call<T = void>(cmd: string, args: object = {}): Promise<T> {
    const id = this.nextId++;
    return new Promise<T>((resolve, reject) => {
      this.calls.set(id, { resolve, reject });
      this.worker.postMessage({ kind: "cmd", id, cmd, ...args });
    });
  }
}
